public static void Run(string input, TraceWriter log)
{
    //do nothing function.  Exists to allow visibility into shared code in Azure functions portal
    log.Info($"C# manually triggered function called with input: {input}");
}