#r "Microsoft.WindowsAzure.Storage"
#r "Newtonsoft.Json"

#load "..\Shared\SharedClasses.csx"
#load "..\Shared\Settings.csx"

#load "..\Shared\ApplicationInsights.csx"

using System.Net;
using Microsoft.WindowsAzure.Storage.Table;
using Newtonsoft.Json;
using Microsoft.ApplicationInsights;
using System.Diagnostics;


private static readonly string FunctionName = "CloudTrax-AddNetwork";
private static string _invocationId; // https://zimmergren.net/getting-the-instance-id-of-a-running-azure-function-with-executioncontext-invocationid/


public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, CloudTable outputTable, ExecutionContext exCtx,TraceWriter log)
{
    _invocationId = exCtx.InvocationId.ToString();
    var telemetryClient = ApplicationInsights.CreateTelemetryClient();
    telemetryClient.Context.Operation.Id=_invocationId;
    telemetryClient.Context.Operation.Name=FunctionName;
    //telemetryClient.TrackEvent(FunctionName);

    var request = StartNewRequest(FunctionName, DateTimeOffset.UtcNow,_invocationId);
    request.Url = req.RequestUri;
    Stopwatch requestTimer = Stopwatch.StartNew();

    try{
        HttpResponseMessage response = await ProcessRequest(req,outputTable);

        telemetryClient.DispatchRequest(request,requestTimer.Elapsed,response.StatusCode,response.IsSuccessStatusCode);
        return response;

    } catch (Exception ex) {
        telemetryClient.TrackException(FunctionName,_invocationId,ex);
        return req.CreateResponse(HttpStatusCode.InternalServerError);
    }
}

private static async Task<HttpResponseMessage> ProcessRequest(HttpRequestMessage req, CloudTable outputTable)
{
    var json = await req.Content.ReadAsStringAsync(); // get the Content into a string
    
    NetworkSecret ns = JsonConvert.DeserializeObject<NetworkSecret>(json); // parse the content as JSON

    if (ns.network_id == null || ns.hashKey ==null)
    {        
        return req.CreateResponse(HttpStatusCode.BadRequest, "Please pass a network name and shared key in the request body");
    } else {

        ns.PartitionKey = ns.network_id;
        ns.RowKey = ns.network_id;
        //fire and forget
        TableOperation operation = TableOperation.InsertOrReplace(ns);
        TableResult result = outputTable.Execute(operation);
        //TODO: Need to check the result
               
        return req.CreateResponse(HttpStatusCode.Created,$"New network ({ns.network_id}) added");
    }
}