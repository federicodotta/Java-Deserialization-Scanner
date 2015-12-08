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
    
    @Override
    public URL getUrl()
    {
        return url;
    }

    @Override
    public String getIssueName()
    {
        return name;
    }

    @Override
    public int getIssueType()
    {
        return 0;
    }

    @Override
    public String getSeverity()
    {
        return severity;
    }

    @Override
    public String getConfidence()
    {
        return confidence;
    }

    @Override
    public String getIssueBackground()
    {
        return null;
    }

    @Override
    public String getRemediationBackground()
    {
        return null;
    }

    @Override
    public String getIssueDetail()
    {
        return issueDetail;
    }

    @Override
    public String getRemediationDetail()
    {
        return remediationDetail;
    }

    @Override
    public IHttpRequestResponse[] getHttpMessages()
    {
        return httpMessages;
    }

    @Override
    public IHttpService getHttpService()
    {
        return httpService;
    }
    
}
