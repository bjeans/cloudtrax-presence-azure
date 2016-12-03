#r "Newtonsoft.Json"

using System.Net;
using System.Text;
using System.Security.Cryptography;
using Newtonsoft.Json;
using System.Configuration;
using Microsoft.WindowsAzure.Storage;
using Microsoft.WindowsAzure.Storage.Table;

public static async Task<HttpResponseMessage> Run(HttpRequestMessage req, CloudTable outputTable, CloudTable inputTable, TraceWriter log)
{
    log.Info("C# HTTP trigger function processed a request.");
    //log.Info(req.Headers.ToString());

    var hmacHeader = req.Headers.GetValues("Signature").FirstOrDefault(); // retreive the Signature from the request header

    //log.Info(hmacHeader);
    var json = await req.Content.ReadAsStringAsync(); // get the Content into a string
    //log.Info(json.ToString());

    //check values and validate Signature

    if (json!=null &&
        hmacHeader!=null /* &&
        sharedSecretKey!=null &&
         */
        )
    {
        
        CloudTraxPing pdata = JsonConvert.DeserializeObject<CloudTraxPing>(json); // parse the content as JSON

        string sharedSecretKey = getSharedSecret(pdata.network_id.ToString(),inputTable); // get the network_id

        if (String.IsNullOrEmpty(sharedSecretKey)) // if we don't have a shared secret we can't validate the message
        {
            
            log.Info($"Unable to retreive shared secret.  Have you added this network?");
            return req.CreateResponse(HttpStatusCode.InternalServerError,$"Unable to retreive shared secret.");

        } else if (!checkSignature(json.ToString(), hmacHeader, sharedSecretKey)){
            
            log.Info("Signature mismatch");
            return req.CreateResponse(HttpStatusCode.Forbidden, "Invalid Signature");

        } else{
        
            log.Info("Signature match");
        
            log.Info($"AP MAC: {pdata.node_mac}"); //which node is Reporting
            log.Info($"Number of reports: {pdata.probe_requests.Count}");

            foreach ( ProbeRequest PR in pdata.probe_requests)
            {
                log.Info($"Device Mac {PR.mac} Count {PR.count} Dates Seen {FromUnixTime(PR.first_seen).ToString("o")} - {FromUnixTime(PR.last_seen).ToString("o")}");
                //dateFormat @"dd\/MM\/yyyy HH:mm:ss"

                ProbeRequest pte = new ProbeRequest() {
                    PartitionKey = pdata.network_id.ToString(),
                    RowKey = PR.mac,
                    mac = PR.mac,
                    count = PR.count,
                    min_signal = PR.min_signal,
                    max_signal = PR.max_signal,
                    avg_signal = PR.avg_signal,
                    last_seen_signal = PR.last_seen_signal,
                    last_seen = PR.last_seen,
                    first_seen = PR.first_seen,
                    associated = PR.associated                
                };

                //fire and forget
                TableOperation operation = TableOperation.InsertOrReplace(pte);
                TableResult result = outputTable.Execute(operation);
                //TODO: Need to check the result             
    
            }
            return req.CreateResponse(HttpStatusCode.OK);    
        }     
    } else {
        return req.CreateResponse(HttpStatusCode.InternalServerError, "Unknown problem occurred");
    }
}
#region Helper Functions

// code inspiration from http://www.epochconverter.com/#code    
    public static System.DateTime FromUnixTime (long unixTime)
    {
        var epoch = new System.DateTime(1970, 1, 1, 0, 0, 0, System.DateTimeKind.Utc);
        return epoch.AddSeconds(unixTime);
    }

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
        TableOperation operation = TableOperation.Retrieve<NetworkSecret>(network_id,network_id);
        TableResult result = inputTable.Execute(operation);
        NetworkSecret ns = (NetworkSecret)result.Result;        
        return ns?.hashKey;
        
    }

#endregion
#region classes to support JSON DeserializeObject

/* Sample data from https://help.cloudtrax.com/hc/en-us/articles/207985916-CloudTrax-Presence-Reporting-API

{"network_id":221234,"node_mac":"AC:86:74:82:9A:30","version":1,"probe_requests":[{"mac":"00:9a:cd:e3:15:49","count":11,"min_signal":-77,"max_signal":-36,"avg_signal":-55,"last_seen_signal":-77,"first_seen":1475860695,"last_seen":1475860718,"associated":false},{"mac":"5c:dc:96:66:24:e3","count":1,"min_signal":-74,"max_signal":-74,"avg_signal":-74,"last_seen_signal":-74,"first_seen":1475860702,"last_seen":1475860702,"associated":false},{"mac":"70:ec:e4:16:75:71","count":1,"min_signal":-58,"max_signal":-58,"avg_signal":-58,"last_seen_signal":-58,"first_seen":1475860708,"last_seen":1475860708,"associated":false},{"mac":"8c:8b:83:d2:26:a5","count":1,"min_signal":-76,"max_signal":-76,"avg_signal":-76,"last_seen_signal":-76,"first_seen":1475860693,"last_seen":1475860693,"associated":false},{"mac":"98:01:a7:9e:47:7f","count":11,"min_signal":-60,"max_signal":-36,"avg_signal":-42,"last_seen_signal":-38,"first_seen":1475860712,"last_seen":1475860718,"associated":false},{"mac":"98:01:a7:a7:1d:d3","count":2,"min_signal":-84,"max_signal":-80,"avg_signal":-82,"last_seen_signal":-84,"first_seen":1475860689,"last_seen":1475860689,"associated":false},{"mac":"a8:86:dd:af:ac:0f","count":1,"min_signal":-68,"max_signal":-68,"avg_signal":-68,"last_seen_signal":-68,"first_seen":1475860708,"last_seen":1475860708,"associated":false},{"mac":"b0:fa:eb:30:4c:9e","count":10,"min_signal":-72,"max_signal":-62,"avg_signal":-67,"last_seen_signal":-67,"first_seen":1475860689,"last_seen":1475860715,"associated":false},{"mac":"e2:9f:fc:7f:1f:42","count":1,"min_signal":-65,"max_signal":-65,"avg_signal":-65,"last_seen_signal":-65,"first_seen":1475860714,"last_seen":1475860714,"associated":false}]}

*/
    
public class ProbeRequest: TableEntity
{
    public string mac { get; set; }
    public int count { get; set; }
    public int min_signal { get; set; }
    public int max_signal { get; set; }
    public int avg_signal { get; set; }
    public int last_seen_signal { get; set; }
    public int first_seen { get; set; }
    public int last_seen { get; set; }
    public bool associated { get; set; }
}

public class CloudTraxPing
{
    public int network_id { get; set; }
    public string node_mac { get; set; }
    public int version { get; set; }
    public List<ProbeRequest> probe_requests { get; set; }
}

public class NetworkSecret : TableEntity
{
    public string network_id { get; set; }
    public string hashKey { get; set; }
}

#endregion