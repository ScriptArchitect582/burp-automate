package burp;

import java.util.ArrayList;
import java.util.List;

public class BurpExtender implements IBurpExtender, IHttpListener, IProxyListener, IScannerListener, IExtensionStateListener
{
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {
        // Set up the callbacks and helpers
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        // Set the name of the extension
        callbacks.setExtensionName("Parameter Finder");

        // Register HTTP listener
        callbacks.registerHttpListener(this);

        // Register proxy listener
        callbacks.registerProxyListener(this);

        // Register scanner listener
        callbacks.registerScannerListener(this);

        // Register extension state listener
        callbacks.registerExtensionStateListener(this);

        // Print message to show that the extension has been loaded
        callbacks.printOutput("Parameter Finder extension loaded.");
    }

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo)
    {
        // Only process requests
        if (messageIsRequest)
        {
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);

            // Get all parameters from the request
            List<IParameter> parameters = requestInfo.getParameters();

            // Modify parameters
            for (IParameter parameter : parameters)
            {
                // Check if the parameter is an URL parameter
                if (parameter.getType() == IParameter.PARAM_URL)
                {
                    // Create a new parameter with modified value
                    IParameter newParameter = helpers.buildParameter(parameter.getName(), parameter.getValue() + " modified", parameter.getType());

                    // Update the request with the modified parameter
                    messageInfo.setRequest(helpers.updateParameter(messageInfo.getRequest(), newParameter));
                }
            }
        }
    }

    @Override
    public void processProxyMessage(boolean messageIsRequest, IInterceptedProxyMessage message)
    {
        // Handle proxy messages
    }

    @Override
    public void newScanIssue(IScanIssue issue)
    {
        // Handle new scan issues
    }

    @Override
    public void extensionUnloaded()
    {
        // Handle extension unload
        callbacks.printOutput("Parameter Finder extension unloaded.");
    }
}
