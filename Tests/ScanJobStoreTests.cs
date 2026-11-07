using Microsoft.VisualStudio.TestTools.UnitTesting;
using VulnerabilityTracker.Services;

namespace VulnerabilityTracker.Tests;

[TestClass]
public sealed class ScanJobStoreTests
{
    [TestMethod]
    public void KeepsStatusTimeAndResultForCompletedScan()
    {
        var store = new ScanJobStore();
        var queued = store.Create();
        var finding = new ScanFinding("SQL001", "Dynamic SQL", "Data.cs", 4);

        Assert.AreEqual(ScanStatus.Queued, queued.Status);
        Assert.IsTrue(store.Start(queued.Id));
        Assert.IsTrue(store.TryGet(queued.Id, out var started));
        Assert.AreEqual(ScanStatus.Running, started!.Status);
        Assert.IsNull(started.Result);
        Assert.IsFalse(store.TryGet(Guid.NewGuid(), out _));

        Assert.IsTrue(store.Complete(started.Id, [finding]));
        Assert.IsTrue(store.TryGet(started.Id, out var completed));
        Assert.AreEqual(ScanStatus.Completed, completed!.Status);
        Assert.IsTrue(completed.StatusChangedAt >= started.StatusChangedAt);
        Assert.AreEqual(finding, completed.Result![0]);
        Assert.IsNull(completed.Error);
        Assert.IsFalse(store.Fail(started.Id, "Late error"));
    }

    [TestMethod]
    public void QueuedJobCannotBeCompletedBeforeItStarts()
    {
        var store = new ScanJobStore();
        var queued = store.Create();

        Assert.IsFalse(store.Complete(queued.Id, []));
        Assert.IsTrue(store.TryGet(queued.Id, out var unchanged));
        Assert.AreEqual(ScanStatus.Queued, unchanged!.Status);
    }
}
