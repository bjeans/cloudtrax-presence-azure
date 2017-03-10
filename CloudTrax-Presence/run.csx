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

private static readonly string FunctionName = "CloudTrax-Presense";
public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, CloudTable outputTable, CloudTable inputTable, TraceWriter log)
{
    log.Info("C# HTTP trigger function processed a request.");
    
    var telemetryClient = ApplicationInsights.CreateTelemetryClient();
    telemetryClient.TrackStatus(FunctionName, "" , "Function triggered by http request");
    
    string hmacHeader;
    IEnumerable<string> sigValues;

    if (req.Headers.TryGetValues("Signature", out sigValues))
    {
        hmacHeader = sigValues.FirstOrDefault();
        //log.Info(hmacHeader);
    
    } else {
         telemetryClient.TrackStatus(FunctionName, "" , "Invalid or missing signature",false);
        // can't find the Signature header so aborting
        return req.CreateResponse(HttpStatusCode.BadRequest, "Missing Signature Header");
    }

    var json = await req.Content.ReadAsStringAsync(); // get the Content into a string

    if (String.IsNullOrEmpty(json) ||  String.IsNullOrEmpty(hmacHeader) ) //we are missing either the signature from the header of the actual JSON content
    {
        if (String.IsNullOrEmpty(hmacHeader)) 
        {
            telemetryClient.TrackStatus(FunctionName, "" , "Invalid or missing signature",false);
            return req.CreateResponse(HttpStatusCode.BadRequest, "Missing Signature"); //should ever get here as this should be caught above
        } else if (String.IsNullOrEmpty(json)) 
        {
            telemetryClient.TrackStatus(FunctionName, "" , "Invalid or missing body",false);
            return req.CreateResponse(HttpStatusCode.BadRequest, "Missing body");
        }        
    }
    else // now we can start to process the data we received
    {
        
        CloudTraxPing pdata = JsonConvert.DeserializeObject<CloudTraxPing>(json); // parse the content as JSON

        string network_id = pdata?.network_id; // get the network_id
        string sharedSecretKey;

        log.Info($"network_id: {network_id}");

        if (String.IsNullOrEmpty(network_id)){
            log.Info($"No network_id found");
            telemetryClient.TrackStatus(FunctionName, "" , "Unable to determine reporting network_id",false);
            return req.CreateResponse(HttpStatusCode.BadRequest,$"Unable to determine reporting network_id");
        } else {

            sharedSecretKey = getSharedSecret(network_id,inputTable); // lookup the sharedSecret from storage table
        }

        if (String.IsNullOrEmpty(sharedSecretKey)) // if we don't have a shared secret we can't validate the message
        {
            
            log.Info($"Unable to retreive shared secret for network {network_id}.  Have you added this network?");
            telemetryClient.TrackStatus(FunctionName, "" , $"Unable to retreive shared secret for network {network_id}.  Have you added this network?",false);
            return req.CreateResponse(HttpStatusCode.BadRequest,$"Unable to retreive shared secret.");

        } 
        else if (checkSignature(json.ToString(), hmacHeader, sharedSecretKey) == false)     //check values and validate Signature
        {
            
            log.Info("Signature mismatch");
            telemetryClient.TrackStatus(FunctionName, "" , $"Invalid Signature.  network_id {network_id}",false);
            return req.CreateResponse(HttpStatusCode.Forbidden, "Invalid Signature");

        } 
        else
        {
        
            //log.Info("Signature match");
        
            log.Info($"AP MAC: {pdata.node_mac}"); //which node is Reporting
            log.Info($"Number of reports: {pdata.probe_requests.Count}");

            foreach ( ProbeRequest PR in pdata.probe_requests)
            {
                log.Info($"Device Mac {PR.mac} Count {PR.count} Dates Seen {FromUnixTime(PR.first_seen).ToString("o")} - {FromUnixTime(PR.last_seen).ToString("o")}");
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

                //fire and forget
                TableOperation operation = TableOperation.InsertOrReplace(pte);
                TableResult result = outputTable.Execute(operation);
                //TODO: Need to check the result             
    
            }
            telemetryClient.TrackStatus(FunctionName, "" , $"Presense data successfully captured {pdata.probe_requests.Count} reports for Network {network_id} ",true);

            return req.CreateResponse(HttpStatusCode.OK);    
        }     
    } 
    
    //if we get here - return a generic error
    telemetryClient.TrackStatus(FunctionName, "" , "Unknown problem occurred",false);

    return req.CreateResponse(HttpStatusCode.InternalServerError, "Unknown problem occurred");

}
#region Helper Functions



    // from http://billatnapier.com/security01.aspx
    public static string ByteToString(byte [] buff)
    {
        string sbinary="";

        for (int i=0;i<buff.Length;i++)
        {
            sbinary+=buff[i].ToString("X2"); // hex format
        }
    return(sbinary);
    }

    // check HMAC Signature - https://help.cloudtrax.com/hc/en-us/articles/207985916-CloudTrax-Presence-Reporting-API
    public static bool checkSignature(string theMessage, string theSignature, string theKey)
    {
        
        System.Text.ASCIIEncoding encoding = new System.Text.ASCIIEncoding();
        byte[] keyByte = encoding.GetBytes(theKey);

        System.Security.Cryptography.HMACSHA256 hmacsha256 = new System.Security.Cryptography.HMACSHA256(keyByte);

        byte[] messageBytes = encoding.GetBytes(theMessage);
        byte[] hashmessage = hmacsha256.ComputeHash(messageBytes);
        
        string hashString = ByteToString(hashmessage);

        return (hashString.ToLower()==theSignature.ToLower()); //convert both to lowercase

    }

    public static string getSharedSecret (string network_id,CloudTable inputTable){
        // PartitionKey = network_id
        // RowKey = network_id
        if (String.IsNullOrEmpty(network_id)){
            return null; // network_id can't be null for table lookup
        } else {
            
            TableOperation operation = TableOperation.Retrieve<NetworkSecret>(network_id,network_id);
            TableResult result = inputTable.Execute(operation);
            NetworkSecret ns = (NetworkSecret)result.Result;        
            return ns?.hashKey;
        }
    }

#endregion
