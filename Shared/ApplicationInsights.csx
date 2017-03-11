
#r "System.Web"

#load "Settings.csx"

using Microsoft.ApplicationInsights;
using Microsoft.ApplicationInsights.DataContracts;
using System.Reflection;
using System.Web.Hosting;
using System.Net;

// from https://github.com/Azure-Samples/ContosoInsurance/blob/master/Src/Cloud/ContosoInsurance.Function/Shared/ApplicationInsights.csx

//Class used to custom events to Application Insights.
public static class ApplicationInsights
{
    public static TelemetryClient CreateTelemetryClient()
    {
        var telemetryClient = new TelemetryClient();
        telemetryClient.InstrumentationKey = Settings.ApplicationInsightsInstrumentationKey;
        return telemetryClient;
    }
}

public enum OperationStatus
{
    Failure = 0,
    Success = 1,
}

public static void TrackStatus(this TelemetryClient client, string functionName, string correlationId, string description, OperationStatus? operationResult = null)
{
    var properties = GetCommonProperties("Status Log", functionName, correlationId);
    properties["Description"] = description;
    if (operationResult.HasValue)
        properties["Status"] = operationResult.ToString();
    var metrics = new Dictionary<string, double> { { "Azure Function", 0 } };
    client.TrackEvent("Azure Function Status", properties, metrics);
}

public static void TrackStatus(this TelemetryClient client, string functionName, string correlationId, string description, bool isSuccess)
{
    var operationResult = isSuccess ? OperationStatus.Success : OperationStatus.Failure;
    TrackStatus(client, functionName, correlationId, description, operationResult);
}

public static void TrackException(this TelemetryClient client, string functionName, string correlationId, Exception ex)
{
    var properties = GetCommonProperties("Error Log", functionName, correlationId);
    properties["LogName"] = "Azure Function Status";
    client.TrackException(ex, properties);
}

private static Dictionary<string, string> GetCommonProperties(string logType, string functionName, string correlationId)
{
    return new Dictionary<string, string>()
    {
        { "LogType", logType},
        { "FunctionName", functionName },
        { "Host",  HostingEnvironment.ApplicationHost?.GetSiteName() },
        { "CorrelationId", correlationId },
        { "Version", Assembly.GetExecutingAssembly().GetName().Version.ToString() },
        { "FunctionsExtensionVersion", Settings.FunctionsExtensionVersion }
    };
}

//https://github.com/Microsoft/ApplicationInsights-Home/blob/master/Samples/AzureEmailService/WorkerRoleB/Telemetry/RequestTelemetryHelper.cs

        public static RequestTelemetry StartNewRequest(string name, DateTimeOffset startTime, string CorrelationId)
        {
            var request = new RequestTelemetry();

            request.Name = name;
            request.Timestamp = startTime;
            request.Id = CorrelationId;

            return request;
        }


        public static void DispatchRequest(this TelemetryClient client, RequestTelemetry request, TimeSpan duration, HttpStatusCode statusCode,bool success)
        {
            request.Duration = duration;
            request.Success = success;
            request.ResponseCode = $"{(int)statusCode} - "+statusCode.ToString();

            client.TrackRequest(request);
        }