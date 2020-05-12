using System.IO;


namespace EllipticCurve.Utils {

    public static class File {

        public static string read(string path) {
            StreamReader sr = new StreamReader(path);
            string content = sr.ReadToEnd();
            sr.Close();
            return content;
        }

        public static byte[] readBytes(string path) {
            return System.IO.File.ReadAllBytes(path);
        }

    }

}
