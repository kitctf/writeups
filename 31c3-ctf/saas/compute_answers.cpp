#include <bits/stdc++.h>
using namespace std;

int main(int argc, char **argv) {
  // array has length n, we want to overwrite a value at offset "offset"
  // (can be >= n, which results in an overflow)
  int n = atoi(argv[1]), offset = atoi(argv[2]);

  vector<uint32_t> x;
  x.resize(2*n);
  for (int i = 0; i < 2*n; ++i)
    x[i] = i;
  // the sort should undo this swap
  swap(x[0], x[offset]);

  vector<int> answers, answers2;

  // these two answers are for __move_median_to_first
  answers.push_back(1);
  answers.push_back(1);
  // this sequence forces __unguarded_partition to return offset + 1
  // then the whole range [0, offset] gets sorted normally
  for (int i = 0; i < offset; ++i)
    answers.push_back(1);
  answers.push_back(0);
  answers.push_back(0);

  int i = 0;
  sort(begin(x), begin(x) + n, [&](int a, int b) {
    if (i < (int)answers.size())
      return (bool)answers[i++];
    else {
      answers2.push_back(a < b);
      return a < b;
    }
  });

  // did the swap work?
  assert(x[0] == 0 && (int)x[offset] == offset);

  // are the elements after the buffer still intact?
  for (int i = n; i < 2*n; ++i)
    if (i != offset)
      assert((int)x[i] == i);

  // print sequence of answers
  cout << "{";
  for (bool x: answers) cout << (x?"true":"false") << ",";
  for (bool x: answers2) cout << (x?"true":"false") << ",";
  cout << "}" << endl;
}
