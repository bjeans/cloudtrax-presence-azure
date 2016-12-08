#r "Newtonsoft.Json"
#load "..\SharedClasses.csx"

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
                    associated = PR.associated,
                    first_seenDT = FromUnixTime(PR.first_seen),
                    last_seenDT = FromUnixTime(PR.last_seen)
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
