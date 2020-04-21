package burp;

import java.net.URL;

public class CustomScanIssue implements IScanIssue {
	
    private IHttpService httpService;
    private URL url;
    private IHttpRequestResponse[] httpMessages;
    private String name;
    private String severity;
    private String confidence;
    private String issueDetail;
    private String remediationDetail;

    public CustomScanIssue(
            IHttpService httpService,
            URL url, 
            IHttpRequestResponse[] httpMessages, 
            String name,
            String severity,
            String confidence,
            String issueDetail,
            String remediationDetail    		
    		)
    {
        this.httpService = httpService;
        this.url = url;
        this.httpMessages = httpMessages;
        this.name = name;
        this.severity = severity;
        this.confidence = confidence;
        this.issueDetail = issueDetail;
        this.remediationDetail = remediationDetail;        
    }
    
    public URL getUrl()
    {
        return url;
    }

    public String getIssueName()
    {
        return name;
    }

    public int getIssueType()
    {
        return 0;
    }

    public String getSeverity()
    {
        return severity;
    }

    public String getConfidence()
    {
        return confidence;
    }

    public String getIssueBackground()
    {
        return null;
    }

    public String getRemediationBackground()
    {
        return null;
    }

    public String getIssueDetail()
    {
        return issueDetail;
    }

    public String getRemediationDetail()
    {
        return remediationDetail;
    }

    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    public IHttpService getHttpService()
    {
        return httpService;
    }
    
}
