using System;
using System.Collections.Generic;
using System.Linq;
using System.Management;
using System.Text;
using System.Threading.Tasks;

namespace Hardware
{
    public class GetMachineDetails
    {
        public static string MachineAndUserSignature()
        {
            ManagementObject os = new ManagementObject("Win32_OperatingSystem=@");
            string ProcessorId = GetProcessorId();
            string WindowsSerial = (string)os["SerialNumber"];
            string DomainName = Environment.UserDomainName;
            string LoginId = Environment.UserName;

            return ProcessorId + "|" + WindowsSerial + "|" + DomainName + "|" + LoginId;
        }

        public static string GetProcessorId()
        {
            try
            {
                StringBuilder sb = new StringBuilder();
                using (System.Management.ManagementClass theClass = new System.Management.ManagementClass("Win32_Processor"))
                {
                    using (System.Management.ManagementObjectCollection theCollectionOfResults = theClass.GetInstances())
                    {
                        foreach (System.Management.ManagementObject currentResult in theCollectionOfResults)
                        {
                            sb.Append(currentResult["ProcessorID"].ToString());
                        }
                    }
                }
                return sb.ToString();
            }
            catch (Exception exception)
            {
                Console.WriteLine(exception.Message);
                return "";
            }
        }
    }
}
