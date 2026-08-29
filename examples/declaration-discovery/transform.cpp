extern "C" int transform(const int* data, int count, int seed)
{
  int a = seed + 3;
  int b = seed ^ 11;
  int c = count;

  for (int index = 0; index < count; ++index) {
    int value = data[index];
    a += (value ^ (b + index)) + ((c << 1) | (value >> 1));
    b = (b * 3) ^ (a + value);
    c += ((a < b) ? value : -value) ^ index;
  }

  if ((a ^ c) < b) {
    a += b - c;
  }
  else {
    b += c - a;
  }

  return (a * 3) ^ (b + c * 5);
}
