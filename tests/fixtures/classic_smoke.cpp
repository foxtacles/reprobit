extern "C" int reprobit_classic_smoke(int left, int right)
{
  int sum = left + right;
  return (sum * 3) ^ (left - right);
}
