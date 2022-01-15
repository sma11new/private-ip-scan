package burp;

/**
 * @Author Sma11New
 * @Github https://github.com/Sma11New
 * @Date 2022-01-15 19:00:27
 */

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class FindIntranetIp {
    /**
     * 正则匹配IP地址列表中的内网地址
     * @param data
     * @return intranetIpList
     */
    public static List<String> getIntranetIps(String data){

        List<String> ipList = getIps(data);

        List<String> ipFilter = new ArrayList<String>();
        List<String> intranetIpList = new ArrayList<String>();

        //A类地址范围：10.0.0.0—10.255.255.255
        ipFilter.add("^10\\.(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[0-9])\\.(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[0-9])\\.(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[0-9])$");
        //B类地址范围: 172.16.0.0---172.31.255.255
        ipFilter.add("^172\\.(1[6789]|2[0-9]|3[01])\\.(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[0-9])\\.(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[0-9])$");
        //C类地址范围: 192.168.0.0---192.168.255.255
        ipFilter.add("^192\\.168\\.(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[0-9])\\.(1\\d{2}|2[0-4]\\d|25[0-5]|[1-9]\\d|[0-9])$");
        // ipFilter.add("127.0.0.1");
        // ipFilter.add("0.0.0.0");

        // 正则编译类型列表，将ipFilter中表达式编译为正则表达式
        List<Pattern> ipFilterRegexList = new ArrayList<>();

        // 循环读取并编译存储
        for (String tmp : ipFilter) {
            ipFilterRegexList.add(Pattern.compile(tmp));
        }

        // 正则匹配内网地址
        for (String ip : ipList) {
            for (Pattern tmp : ipFilterRegexList) {
                Matcher matcher = tmp.matcher(ip);
                if (matcher.find()) {
                    intranetIpList.add(ip);
                }
            }
        }
        return intranetIpList;
    }

    /**
     * 正则匹配String中的IP地址
     * @param data
     * @return ipList
     */
    private static List<String> getIps(String data) {

        String regEx="((2[0-4]\\d|25[0-5]|[01]?\\d\\d?)\\.){3}(2[0-4]\\d|25[0-5]|[01]?\\d\\d?)";
        List<String> ipList = new ArrayList<String>();

        // 创建正则对象
        Pattern p = Pattern.compile(regEx);
        Matcher m = p.matcher(data);

        // 循环匹配IP地址
        while (m.find()) {
            String result = m.group();
            ipList.add(result);
        }
        return ipList;
    }
}
