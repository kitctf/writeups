#include <bits/stdc++.h>
#include "mysort.h"
using namespace std;

int main(int argc, char **argv) {
  // array has length n, we want to overwrite a value at offset "offset"
  // (can be >= n, which results in an overflow)
  int n = atoi(argv[1]);
  int offset = atoi(argv[2]);

  vector<uint32_t> x;
  x.resize(2*n);
  for (int i = 0; i < 2*n; ++i)
    x[i] = i;
  // the sort should undo this swap
  swap(x[0], x[offset]);

  vector<int> answers, answers2;

  // this sequence forces unguarded_partition to return offset + 1
  // then the whole range [0, offset] gets sorted normally
  answers.push_back(1);
  answers.push_back(1);
  for (int i = 0; i < offset; ++i)
    answers.push_back(1);
  answers.push_back(0);
  answers.push_back(0);

  int i = 0;
  _sort(begin(x), begin(x) + n, [&](int a, int b) {
    if (i < (int)answers.size())
      return (bool)answers[i++];
    else {
      answers2.push_back(a < b);
      return a < b;
    }
  });

  // did the swap work?
  assert(x[0] == 0 && (int)x[offset] == offset);

  // print sequence of answers
  cout << "{";
  for (bool x: answers) cout << (x?"true":"false") << ",";
  for (bool x: answers2) cout << (x?"true":"false") << ",";
  cout << "}" << endl;
}
