const int S_threshold = 16;

// this is the function we will primarily use for our exploit
template<typename It, typename F>
It unguarded_partition(It first, It last, It pivot, F comp) {
  while (true) {
    // we can control exactly the return value of this function by sending
    // answering with a sequence of "true"s
    while (comp(*first, *pivot))
      ++first;
    --last;
    while (comp(*pivot, *last))
      --last;
    // this will always be true if we incremented "first" past the end of the
    // buffer
    if (!(first < last))
      return first;
    std::swap(*first, *last);
    ++first;
  }
}

// Swaps the median value of *__a, *__b and *__c under __comp to *__result
template<typename It, typename F>
void move_median_to_first(It result, It a, It b, It c, F comp) {
  if (comp(*a, *b)) {
    if (comp(*b, *c))
      std::swap(*result, *b);
    else if (comp(*a, *c))
      std::swap(*result, *c);
    else
      std::swap(*result, *a);
  }
  else if (comp(*a, *c))
    std::swap(*result, *a);
  else if (comp(*b, *c))
    std::swap(*result, *c);
  else
    std::swap(*result, *b);
}

template<typename It, typename F>
It unguarded_partition_pivot(It first, It last, F comp) {
  It mid = first + (last - first) / 2;
  move_median_to_first(first, first + 1, mid, last - 1, comp);
  return unguarded_partition(first + 1, last, first, comp);
}

template<typename It, typename F>
void _partial_sort(It first, It middle, It last, F compare) {
  assert(0);
}

// introsort is basically quicksort with a fallback to heap sort in degenerate
// cases. For our use case, we will never reach the heap sort, so we didn't
// need to add it here.
template<typename It, typename F>
void introsort_loop(It first, It last, int depth_limit, F comp) {
  while (last - first > int(S_threshold)) {
    if (depth_limit == 0) {
      _partial_sort(first, last, last, comp);
      return;
    }
    --depth_limit;
    // place pivot. We control the return value here!
    It cut = unguarded_partition_pivot(first, last, comp);
    // recurse into the right half
    introsort_loop(cut, last, depth_limit, comp);
    // use explicit tail recursion for the left half, to save stack space
    last = cut;
  }
}

// computes the logarithm of n in base 2
inline int lg(int n) {
  int k;
  for (k = 0; n != 1; n >>= 1) ++k;
  return k;
}

// the whole insertion sort doesn't really interest us
template<typename It, typename F>
void unguarded_linear_insert(It last, F comp) {
  auto val = *last;
  It next = last;
  --next;
  while (comp(val, *next)) {
    *last = *next;
    last = next;
    --next;
  }
  *last = val;
}

template<typename It, typename F>
void insertion_sort(It first, It last, F comp) {
  if (first == last) return;
  for (It i = first + 1; i != last; ++i) {
    if (comp(*i, *first)) {
      auto val = *i;
      move_backward(first, i, i + 1);
      *first = val;
    } else {
      unguarded_linear_insert(i, comp);
    }
  }
}

template<typename It, typename F>
void unguarded_insertion_sort(It first, It last, F comp) {
  for (It i = first; i != last; ++i)
    unguarded_linear_insert(i, comp);
}

template<typename It, typename F>
void final_insertion_sort(It first, It last, F comp) {
  if (last - first > int(S_threshold)) {
    insertion_sort(first, first + int(S_threshold), comp);
    unguarded_insertion_sort(first + int(S_threshold), last, comp);
  } else {
    insertion_sort(first, last, comp);
  }
}

// sort
template<typename It, typename F>
inline void _sort(It first, It last, F comp) {
  if (first != last) {
    // first we do introsort until the array is almost sorted
    // (we don't solve subproblems below a certain size)
    introsort_loop(first, last, lg(last - first) * 2, comp);
    // we fix the final order using an insertion sort pass
    final_insertion_sort(first, last, comp);
  }
}
