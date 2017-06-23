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

private static readonly string FunctionName = "GuestWiFiRedirect";
private static readonly string defaultRedirectURL="http://google.com";
private static string _invocationId; // https://zimmergren.net/getting-the-instance-id-of-a-running-azure-function-with-executioncontext-invocationid/
public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, CloudTable outputTable, ExecutionContext exCtx, TraceWriter log)
{
    _invocationId = exCtx.InvocationId.ToString();

    var telemetryClient = ApplicationInsights.CreateTelemetryClient();
    telemetryClient.Context.Operation.Id=_invocationId;
    telemetryClient.Context.Operation.Name=FunctionName;

    var request = StartNewRequest(FunctionName, DateTimeOffset.UtcNow,_invocationId);
    request.Url = req.RequestUri;
    Stopwatch requestTimer = Stopwatch.StartNew();
    
    try {
        HttpResponseMessage response = await ProcessRequest(req,outputTable, telemetryClient,log);

        telemetryClient.DispatchRequest(request,requestTimer.Elapsed,response.StatusCode,(response.StatusCode==HttpStatusCode.Redirect));
        return response;

    } catch (Exception ex) {
        telemetryClient.TrackException(FunctionName,_invocationId,ex);
        return req.CreateResponse(HttpStatusCode.InternalServerError);
    }
    
}



private static async Task<HttpResponseMessage> ProcessRequest(HttpRequestMessage req,  CloudTable outputTable,TelemetryClient telemetry, TraceWriter log)

{
    log.Info("C# HTTP trigger function processed a request.");

    IEnumerable<KeyValuePair<string, string>>  Params = req.GetQueryNameValuePairs();
    
    Uri destination=new Uri(defaultRedirectURL);

    GuestLogon gl = new GuestLogon();

    foreach (KeyValuePair<string, string> kvp  in Params){
        log.Info($"Key: {kvp.Key} = {kvp.Value}");
        if (kvp.Key=="client_url"){
            gl.client_url = kvp.Value;
        } else if (kvp.Key=="node_mac"){
            gl.node_mac = kvp.Value;
        } else if (kvp.Key=="client_mac"){
            gl.client_mac = kvp.Value;
        } else if (kvp.Key=="gw_name"){
            gl.gw_name = kvp.Value;        
        }
    }
    gl.PartitionKey = gl.client_mac;
    gl.RowKey = System.DateTime.Now.ToUniversalTime().ToString("o"); //time format https://docs.microsoft.com/en-us/dotnet/standard/base-types/standard-date-and-time-format-strings

    var success = false;
    var startTime = DateTime.UtcNow;
    var timer = System.Diagnostics.Stopwatch.StartNew();
    try
    {
        //fire and forget
        TableOperation operation = TableOperation.Insert(gl);

        //should look at making this call async
        TableResult result = outputTable.Execute(operation);
        //await outputTable.ExecuteAsync(operation);
        //TODO: Need to check the result             
        success = true;
    }
    finally
    {
        timer.Stop();
        telemetry.TrackDependency("AzureTables", "Insert", startTime, timer.Elapsed, success);
    }


    var response = req.CreateResponse(HttpStatusCode.Redirect);
        response.Headers.Location = new Uri(gl.client_url);
    return  response;
}

public class GuestLogon : TableEntity
{
    public string node_mac {get; set;}
    public string gw_name {get; set;}
    public string client_mac {get; set;}
    public string client_url {get; set;}
}