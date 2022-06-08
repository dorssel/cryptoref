using System.Reflection;

namespace UnitTests
{
    [AttributeUsage(AttributeTargets.Method)]
    internal class NistShakeMsgDataSourceAttribute
        : Attribute
        , ITestDataSource
    {
        public NistShakeMsgDataSourceAttribute(int L)
        {
            this.L = L;
        }

        readonly int L;
        public bool QuickTest = false;

        static readonly int[] SmallQuickLengths = { 0, 1, 7, 8, 9, 100 };

        public IEnumerable<object[]> GetData(MethodInfo methodInfo)
        {
            var selected = NistShakeMsgTestVector.All.Where(tv => tv.L == L);
            if (QuickTest)
            {
                selected = selected.Where(tv => SmallQuickLengths.Contains(tv.Msg.Length))
                    .Append(selected.First(tv => tv.Msg.Length >= 10000))
                    .Append(selected.MinBy(tv => tv.Outputlen) ?? throw new InternalTestFailureException())
                    .Append(selected.MaxBy(tv => tv.Outputlen) ?? throw new InternalTestFailureException());
            }
            return selected.Select(tv => new object[] { tv.Msg, tv.Outputlen, tv.Output });
        }

        public string GetDisplayName(MethodInfo methodInfo, object[] data)
        {
            var Msg = (string)data[0];
            var Outputlen = (int)data[1];
            return $"{methodInfo.Name}({Msg.Length}, {Outputlen})";
        }
    }
}
