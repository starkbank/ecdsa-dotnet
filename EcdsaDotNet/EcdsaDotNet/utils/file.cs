using System.IO;


namespace EllipticCurve.Utils {

    public static class File {

        public static string read(string path) {
            using StreamReader sr = new StreamReader(path);
            return sr.ReadToEnd();
        }

    }

}
