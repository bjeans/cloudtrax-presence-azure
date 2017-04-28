#r "Newtonsoft.Json"
#load "..\Shared\SharedClasses.csx"

#load "..\Shared\Settings.csx"

#load "..\Shared\ApplicationInsights.csx"

using System.Net;
using System.Text;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.Configuration;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;
using Microsoft.ApplicationInsights;
using System.Diagnostics;

private static readonly string FunctionName = "CloudTrax-Presence";
private static string _invocationId; // https://zimmergren.net/getting-the-instance-id-of-a-running-azure-function-with-executioncontext-invocationid/
public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, CloudTable outputTable, CloudTable inputTable, ExecutionContext exCtx, TraceWriter log)
{
    _invocationId = exCtx.InvocationId.ToString();

    var telemetryClient = ApplicationInsights.CreateTelemetryClient();
    telemetryClient.Context.Operation.Id=_invocationId;
    telemetryClient.Context.Operation.Name=FunctionName;

    var request = StartNewRequest(FunctionName, DateTimeOffset.UtcNow,_invocationId);
    request.Url = req.RequestUri;
    Stopwatch requestTimer = Stopwatch.StartNew();
    
    try {
        HttpResponseMessage response = await ProcessRequest(req,outputTable,inputTable,telemetryClient);

        telemetryClient.DispatchRequest(request,requestTimer.Elapsed,response.StatusCode,response.IsSuccessStatusCode);
        return response;

    } catch (Exception ex) {
        telemetryClient.TrackException(FunctionName,_invocationId,ex);
        return req.CreateResponse(HttpStatusCode.InternalServerError);
    }
    
}

// private static async Task<HttpResponseMessage> ProcessRequest(HttpRequestMessage req, CloudTable outputTable, CloudTable inputTable){
//     return await ProcessRequest(req,outputTable,inputTable,null);
// }
private static async Task<HttpResponseMessage> ProcessRequest(HttpRequestMessage req, CloudTable outputTable, CloudTable inputTable, TelemetryClient telemetry)
{
    string hmacHeader;
    IEnumerable<string> sigValues;

    if (req.Headers.TryGetValues("Signature", out sigValues))
    {
        hmacHeader = sigValues.FirstOrDefault();
    
    } else {
        // can't find the Signature header so aborting
        return req.CreateResponse(HttpStatusCode.BadRequest, "Missing Signature Header");
    }

    var json = await req.Content.ReadAsStringAsync(); // get the Content into a string

    if (String.IsNullOrEmpty(json) ||  String.IsNullOrEmpty(hmacHeader) ) //we are missing either the signature from the header of the actual JSON content
    {
        if (String.IsNullOrEmpty(hmacHeader)) 
        {
            return req.CreateResponse(HttpStatusCode.BadRequest, "Missing Signature"); //should ever get here as this should be caught above
        } else if (String.IsNullOrEmpty(json)) 
        {
            return req.CreateResponse(HttpStatusCode.BadRequest, "Missing body");
        }        
    }
    else // now we can start to process the data we received
    {
        
        CloudTraxPing pdata = JsonConvert.DeserializeObject<CloudTraxPing>(json); // parse the content as JSON

        string network_id = pdata?.network_id; // get the network_id
        string sharedSecretKey;

        //log.Info($"network_id: {network_id}");

        if (String.IsNullOrEmpty(network_id)){
            return req.CreateResponse(HttpStatusCode.BadRequest,$"Unable to determine reporting network_id");
        } else {
            sharedSecretKey = getSharedSecret(network_id,inputTable); // lookup the sharedSecret from storage table
        }

        if (String.IsNullOrEmpty(sharedSecretKey)) // if we don't have a shared secret we can't validate the message
        {            
            return req.CreateResponse(HttpStatusCode.BadRequest,$"Unable to retreive shared secret.");
        } 
        else if (checkSignature(json.ToString(), hmacHeader, sharedSecretKey) == false)     //check values and validate Signature
        {                        
            return req.CreateResponse(HttpStatusCode.Forbidden, "Invalid Signature");
        } 
        else
        {        
            //log.Info($"AP MAC: {pdata.node_mac}"); //which node is Reporting
            //log.Info($"Number of reports: {pdata.probe_requests.Count}");

            foreach ( ProbeRequest PR in pdata.probe_requests)
            {
                //log.Info($"Device Mac {PR.mac} Count {PR.count} Dates Seen {FromUnixTime(PR.first_seen).ToString("o")} - {FromUnixTime(PR.last_seen).ToString("o")}");
                //dateFormat @"dd\/MM\/yyyy HH:mm:ss"

                ProbeRequest pte = new ProbeRequest() {
                    PartitionKey = network_id,
                    RowKey = PR.mac,
                    mac = PR.mac,
                    count = PR.count,
                    min_signal = PR.min_signal,
                    max_signal = PR.max_signal,
                    avg_signal = PR.avg_signal,
                    last_seen_signal = PR.last_seen_signal,
                    last_seen = PR.last_seen,
                    first_seen = PR.first_seen,
                    associated = PR.associated,
                    first_seenDT = FromUnixTime(PR.first_seen),
                    last_seenDT = FromUnixTime(PR.last_seen)
                };


                // https://docs.microsoft.com/en-us/azure/application-insights/app-insights-api-custom-events-metrics#trackdependency
                var success = false;
                var startTime = DateTime.UtcNow;
                var timer = System.Diagnostics.Stopwatch.StartNew();
                try
                {
                    //fire and forget
                    TableOperation operation = TableOperation.InsertOrReplace(pte);

                    //should look at making this call async
                    TableResult result = outputTable.Execute(operation);
                    //TODO: Need to check the result             
                    success = true;
                }
                finally
                {
                    timer.Stop();
                    telemetry.TrackDependency("AzureTables", "InsertOrReplace", startTime, timer.Elapsed, success);
                }
                
            }
            if (telemetry!=null){
                telemetry.TrackMetric("Devices Seen", pdata.probe_requests.Count);
            }
            return req.CreateResponse(HttpStatusCode.OK);    
        }     
    } 
    
    //if we get here - return a generic error

    return req.CreateResponse(HttpStatusCode.InternalServerError, "Unknown problem occurred");


}