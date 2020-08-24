using System.IO;
using System;

public class PathFixture : IDisposable
{
    public PathFixture()
    {
        string path = Path.Combine(Directory.GetCurrentDirectory(), "../../..");
        Directory.SetCurrentDirectory(path);
    }

    public void Dispose()
    {

    }
}