#r "Microsoft.WindowsAzure.Storage"
#r "Newtonsoft.Json"


using System.Net;
using Microsoft.WindowsAzure.Storage.Table;
using Newtonsoft.Json;

public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, CloudTable outputTable, TraceWriter log)
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

        return req.CreateResponse(HttpStatusCode.Created);
    }

    
    
}

public class NetworkSecret : TableEntity
{
    public string network_id { get; set; }
    public string hashKey { get; set; }
}