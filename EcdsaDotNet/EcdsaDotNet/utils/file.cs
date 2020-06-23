namespace EllipticCurve.Utils {

    public static class File {

        public static string read(string path) {
            return System.IO.File.ReadAllText(path);
        }

        public static byte[] readBytes(string path) {
            return System.IO.File.ReadAllBytes(path);
        }

    }

}
