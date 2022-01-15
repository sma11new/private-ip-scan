package burp;

/**
 * @Author Sma11New
 * @Github https://github.com/Sma11New
 * @Date 2022-01-15 08:26:27
 */

import java.io.PrintWriter;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class BurpExtender implements IBurpExtender, IHttpListener {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private String ExtensionName = "Private IP Scan";
    private List<URL> urlList = new ArrayList<>(); // 已发现漏洞的地址（确保不重复输出）

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        callbacks.setExtensionName(ExtensionName);
        helpers = callbacks.getHelpers();
        stdout = new PrintWriter(callbacks.getStdout(), true);
        String successOutputData = "[+] Version: 0.1\n[+] Author: Sma11New\n";
        successOutputData += "[+] Github: https://github.com/Sma11New/Private IP Scan\n";
        successOutputData += "Description: Private address leak scanning plugin, the result is in the Extender plugin output interface\n";
        successOutputData += "-------------------------------------------------\n";
        stdout.println(successOutputData);

        callbacks.registerHttpListener(this);
    }

    // 处理所有HTTP数据
    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {

        // 只关注响应包
        if (! messageIsRequest) {
            IResponseInfo analyzedResponse = helpers.analyzeResponse(messageInfo.getResponse()); // getResponse获得的是字节序列
            String resp = new String(messageInfo.getResponse());

            int bodyOffset = analyzedResponse.getBodyOffset();
            String body = resp.substring(bodyOffset);

            List<String> intranetIpList = FindIntranetIp.getIntranetIps(body);

            // 获取漏洞URL
            URL url;
            try {
                url = helpers.analyzeRequest(messageInfo).getUrl();
            } catch (UnsupportedOperationException e) {
                url = null;
            }

            // 获取时间
            Date day=new Date();
            SimpleDateFormat df = new SimpleDateFormat("HH:mm:ss");

            if (intranetIpList.size() > 0) {
                // 判断是否已经存在该URL，不存在则输出并添加
                if (! urlList.contains(url)) {
                    stdout.println("[Private IP] - [" + df.format(day) + "] - " + url + " - " + intranetIpList);
                    urlList.add(url);
                }
            }
        }
    }
}


