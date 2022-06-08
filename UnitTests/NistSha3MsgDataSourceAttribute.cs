using System.Reflection;

namespace UnitTests
{
    [AttributeUsage(AttributeTargets.Method)]
    internal class NistSha3MsgDataSourceAttribute
        : Attribute
        , ITestDataSource
    {
        public NistSha3MsgDataSourceAttribute(int L)
        {
            this.L = L;
        }

        readonly int L;
        public bool QuickTest = false;

        static readonly int[] SmallQuickLengths = { 0, 1, 7, 8, 9, 100 };

        public IEnumerable<object[]> GetData(MethodInfo methodInfo)
        {
            var selected = NistSha3MsgTestVector.All.Where(tv => tv.L == L);
            if (QuickTest)
            {
                selected = selected.Where(tv => SmallQuickLengths.Contains(tv.Msg.Length))
                    .Append(selected.First(tv => tv.Msg.Length >= 10000));
            }
            return selected.Select(tv => new object[] { tv.Msg, tv.MD });
        }

        public string GetDisplayName(MethodInfo methodInfo, object[] data)
        {
            var Msg = (string)data[0];
            return $"{methodInfo.Name}({Msg.Length})";
        }
    }
}
