using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using NDesk.Options;

namespace inept_net
{
    class Program
    {
        public class SettingsClass
        {
            public SettingsClass()
            {
                Tracelevel = 4;
            }

            public int Tracelevel { get; set; }
        }

        public static SettingsClass Settings {get;private set;}

        static void Main(string[] args)
        {
            ArgParse(args);
        }

        private static void ArgParse(string[] args)
        {
            bool show_help = false;
            //List<string> names = new List<string>();
            //int repeat = 1;

            Settings = new SettingsClass();
            

            var p = new OptionSet() {
                //{ "n|name=", "the {NAME} of someone to greet.",
                //   v => names.Add (v) },
                //{ "r|repeat=", 
                //   "the number of {TIMES} to repeat the greeting.\n" + 
                //      "this must be an integer.",
                //    (int v) => repeat = v },
                { "v", "increase debug message verbosity",
                   v => { if (v != null) Settings.Tracelevel = Settings.Tracelevel+1; } },
                { "t|tracelevel=", "Set tracelevel",
                   (int v) => Settings.Tracelevel = v },
                { "h|help",  "show this message and exit", 
                   v => show_help = v != null },
            };

            List<string> extra;
            try
            {
                extra = p.Parse(args);
            }
            catch (OptionException e)
            {
                Console.Write("inept_net: ");
                Console.WriteLine(e.Message);
                Console.WriteLine("Try `--help' for more information.");
                return;
            }
        }

        
    }
}
