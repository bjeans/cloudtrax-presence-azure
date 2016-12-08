#r "Microsoft.WindowsAzure.Storage"


using Microsoft.WindowsAzure.Storage.Table;

// code inspiration from http://www.epochconverter.com/#code    
    public static System.DateTime FromUnixTime (long unixTime)
    {
        var epoch = new System.DateTime(1970, 1, 1, 0, 0, 0, System.DateTimeKind.Utc);
        return epoch.AddSeconds(unixTime);
    }

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
    public DateTime first_seenDT {get; set;}
    public DateTime last_seenDT {get; set;}
    public bool associated { get; set; }
    [IgnoreProperty] //don't serialize to AzureTables - https://blogs.msdn.microsoft.com/windowsazurestorage/2013/09/06/announcing-storage-client-library-2-1-rtm-ctp-for-windows-phone/
    public int first_seen { get; set; } //need this for JSON DeserializeObject
    [IgnoreProperty]
    public int last_seen { get; set; } //need this for JSON DeserializeObject
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