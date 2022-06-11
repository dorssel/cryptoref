using System.Reflection;

namespace UnitTests
{
    [AttributeUsage(AttributeTargets.Method)]
    internal class NistKmacSampleDataSourceAttribute
        : Attribute
        , ITestDataSource
    {
        public NistKmacSampleDataSourceAttribute(int SecurityStrength)
        {
            this.SecurityStrength = SecurityStrength;
        }

        readonly int SecurityStrength;

        public IEnumerable<object[]> GetData(MethodInfo methodInfo)
        {
            var selected = NistKmacSampleTestVector.All.Where(tv => tv.SecurityStrength == SecurityStrength);
            return selected.Select(tv => new object[] { tv });
        }

        public string GetDisplayName(MethodInfo methodInfo, object[] data)
        {
            var testVector = (NistKmacSampleTestVector)data[0];
            return $"{methodInfo.Name}(Sample {testVector.Sample})";
        }
    }
}
