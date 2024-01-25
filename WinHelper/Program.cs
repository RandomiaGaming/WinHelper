using System.Threading;

namespace WinHelper
{
	public static class Program
	{
		public static void Main(string[] args)
		{
			SetUACHighest();
		}

		[System.Runtime.InteropServices.DllImport("user32.dll", CharSet = System.Runtime.InteropServices.CharSet.Auto)]
		public static extern System.IntPtr SendMessage(System.IntPtr hWnd, uint Msg, uint wParam, [System.Runtime.InteropServices.MarshalAs(System.Runtime.InteropServices.UnmanagedType.LPWStr)] string lParam);

		public static void CheckSystem()
		{
			CheckHiddenFiles();
			SetUACHighest();
			SecureAdmin();
		}
		public static void SetUACHighest()
		{
			SetRegistryValue("SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon", "DisableCAD", 1, Microsoft.Win32.RegistryValueKind.DWord);
			SetRegistryValue("SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power", "HiberBootEnabled", 1, Microsoft.Win32.RegistryValueKind.DWord);
			SetRegistryValue("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\CredUI", "EnableSecureCredentialPrompting", 0, Microsoft.Win32.RegistryValueKind.DWord);
			SetRegistryValue("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "EnableLUA", 1, Microsoft.Win32.RegistryValueKind.DWord);
			SetRegistryValue("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "PromptOnSecureDesktop", 0, Microsoft.Win32.RegistryValueKind.DWord);
			SetRegistryValue("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "ConsentPromptBehaviorAdmin", 2, Microsoft.Win32.RegistryValueKind.DWord);
			SetRegistryValue("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "ConsentPromptBehaviorUser", 1, Microsoft.Win32.RegistryValueKind.DWord);
		}
		public static void SecureAdmin()
		{
			System.Console.WriteLine("Enter a secure and memorable password for the administrator account:");
			string password = System.Console.ReadLine();
			RunCMDCommand("net.exe", "user administrator /active:yes");
			RunCMDCommand("net.exe", $"user administrator \"{password}\"");
			string output = RunCMDCommand("net.exe", $"localgroup administrators").Replace("\r", "");
			string[] outputSplit = output.Split('\n');
			int startIndex = -1;
			int endIndex = -1;
			for (int i = 0; i < outputSplit.Length; i++)
			{
				if (outputSplit[i] == "-------------------------------------------------------------------------------")
				{
					if (startIndex != -1)
					{
						throw new System.Exception();
					}
					startIndex = i;
				}
				if (outputSplit[i] == "The command completed successfully.")
				{
					if (startIndex == -1)
					{
						throw new System.Exception();
					}
					endIndex = i;
					break;
				}
			}
			if (startIndex == -1 || endIndex == -1)
			{
				throw new System.Exception();
			}
			for (int i = startIndex + 1; i < endIndex; i++)
			{
				if (outputSplit[i].ToLower() != "administrator")
				{
					RunCMDCommand("net.exe", $"localgroup administrators /delete \"{outputSplit[i]}\"");
				}
			}
			RunCMDCommand("shutdown.exe", "/r /t 0");
		}
		public static void CheckHiddenFiles()
		{
			SetRegistryValue("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "Hidden", 1, Microsoft.Win32.RegistryValueKind.DWord);
			SetRegistryValue("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "ShowSuperHidden", 1, Microsoft.Win32.RegistryValueKind.DWord);
			SetRegistryValue("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "DontPrettyPath", 1, Microsoft.Win32.RegistryValueKind.DWord);
			SetRegistryValue("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\Advanced", "HideFileExt", 0, Microsoft.Win32.RegistryValueKind.DWord);

			foreach (System.Diagnostics.Process process in System.Diagnostics.Process.GetProcesses())
			{
				try
				{
					string mainModuleFilePath = GetMainModuleFileName(process);
					if (mainModuleFilePath.ToLower().EndsWith("explorer.exe"))
					{
						process.Kill();
					}
				}
				catch
				{

				}
			}
		}
		public static string RunCMDCommand(string processFilePath, string arguments)
		{
			System.Diagnostics.ProcessStartInfo processStartInfo = new System.Diagnostics.ProcessStartInfo();
			processStartInfo.FileName = processFilePath;
			processStartInfo.Arguments = arguments;
			processStartInfo.UseShellExecute = false;
			processStartInfo.RedirectStandardOutput = true;
			System.Diagnostics.Process process = System.Diagnostics.Process.Start(processStartInfo);
			process.WaitForExit();
			return process.StandardOutput.ReadToEnd();
		}
		public static void SetRegistryValue(string keyPath, string valueName, object value, Microsoft.Win32.RegistryValueKind valueKind)
		{
			Microsoft.Win32.RegistryKey HKCU32 = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Registry32);
			Microsoft.Win32.RegistryKey HKCU64 = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.CurrentUser, Microsoft.Win32.RegistryView.Registry64);
			Microsoft.Win32.RegistryKey HKLM32 = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry32);
			Microsoft.Win32.RegistryKey HKLM64 = Microsoft.Win32.RegistryKey.OpenBaseKey(Microsoft.Win32.RegistryHive.LocalMachine, Microsoft.Win32.RegistryView.Registry64);

			Microsoft.Win32.RegistryKey HKCU32Key = HKCU32.CreateSubKey(keyPath, true);
			Microsoft.Win32.RegistryKey HKCU64Key = HKCU64.CreateSubKey(keyPath, true);
			Microsoft.Win32.RegistryKey HKLM32Key = HKLM32.CreateSubKey(keyPath, true);
			Microsoft.Win32.RegistryKey HKLM64Key = HKLM64.CreateSubKey(keyPath, true);

			HKCU32Key.SetValue(valueName, value, valueKind);
			HKCU64Key.SetValue(valueName, value, valueKind);
			HKLM32Key.SetValue(valueName, value, valueKind);
			HKLM64Key.SetValue(valueName, value, valueKind);

			HKCU32Key.Close();
			HKCU64Key.Close();
			HKLM32Key.Close();
			HKLM64Key.Close();

			HKCU32Key.Dispose();
			HKCU64Key.Dispose();
			HKLM32Key.Dispose();
			HKLM64Key.Dispose();

			HKCU32.Close();
			HKCU64.Close();
			HKLM32.Close();
			HKLM64.Close();

			HKCU32.Dispose();
			HKCU64.Dispose();
			HKLM32.Dispose();
			HKLM64.Dispose();
		}
		[System.Runtime.InteropServices.DllImport("Kernel32.dll", SetLastError = true)]
		private static extern bool QueryFullProcessImageName([System.Runtime.InteropServices.In] System.IntPtr hProcess, [System.Runtime.InteropServices.In] uint dwFlags, [System.Runtime.InteropServices.Out] System.Text.StringBuilder lpExeName, [System.Runtime.InteropServices.In, System.Runtime.InteropServices.Out] ref uint lpdwSize);
		public static string GetMainModuleFileName(System.Diagnostics.Process process, int buffer = 2048)
		{
			var fileNameBuilder = new System.Text.StringBuilder(buffer);
			uint bufferLength = (uint)fileNameBuilder.Capacity + 1;
			bool output = QueryFullProcessImageName(process.Handle, 0, fileNameBuilder, ref bufferLength);
			if (output)
			{
				return fileNameBuilder.ToString();
			}
			else
			{
				return null;
			}
		}
	}
}