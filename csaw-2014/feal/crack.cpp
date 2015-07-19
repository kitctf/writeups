#include <bits/stdc++.h>
using namespace std;

struct Block {
    uint32_t value;
    Block(uint32_t value=0):value(value){}
    Block(const Block& other):value(other.value){}
    Block operator^(Block other) const{ return {value ^ other.value}; }
    bool operator==(Block other) const{ return value == other.value; }
    bool operator!=(Block other) const{ return !(*this == other); }
};

uint8_t rot3(uint8_t x) {
    return (x<<3)|(x>>5);
}

uint8_t gBox(uint8_t a,uint8_t b,uint8_t mode) {
    return rot3(a+b+mode);
}

uint8_t get_byte(Block b, int i) {
    return (b.value>>((3-i)<<3));
}
Block fBox(Block plain) {
    auto t0 = get_byte(plain,2) ^ get_byte(plain,3);
    uint32_t y1 = gBox(get_byte(plain,0) ^ get_byte(plain,1), t0, 1);
    uint32_t y0 = gBox(get_byte(plain,0), y1, 0);
    uint32_t y2 = gBox(t0, y1, 0);
    uint32_t y3 = gBox(get_byte(plain,3), y2, 1);
    return Block{(y3<<24) | (y2<<16) | (y1<<8) | y0};
}

Block read_block() {
    Block res;
    for (int i = 0; i < 4; ++i) {
        int x; cin >> x;
        res.value = (res.value<<8) | x;
    }
    return res;
}

ostream& operator<<(ostream& o, Block a) {
    o << "[";
    for (int i = 0; i < 4; ++i) {
        if (i > 0) o << ", ";
        o << (int)get_byte(a, i);
    }
    return o << "]";
}

Block keys[6];
vector<tuple<Block,Block,Block,Block>> pt_pairs[5], ct_pairs[5];
vector<Block> diffs[5];

pair<Block, Block> partial_decrypt(int round, Block c0, Block c1) {
    Block l = c0 ^ c1, r = c0;
    for (int i = 4; i >= round; --i) {
        Block tmp = l;
        l = fBox(l ^ keys[i-1]) ^ r;
        r = tmp;
    }
    return {l, r};
}

bool solve_round(int round, int ind=0) {
    if (round == 0) {
        Block cl, cr, pl, pr;
        cl = get<0>(ct_pairs[1][0]);
        cr = get<1>(ct_pairs[1][0]);
        pl = get<0>(pt_pairs[1][0]);
        pr = get<1>(pt_pairs[1][0]);
        auto p = partial_decrypt(1, cl, cr);
        keys[4] = pl ^ p.first;
        keys[5] = pr ^ p.first ^ p.second;
        cout << "YAY: keys=[" << endl;
        for (int i = 0; i < 6; ++i)
            cout << "  " << keys[i] << ", " << endl;
        cout << "]" << endl;
        return true;
    }
    for (uint32_t k = 0; ; ++k) {
        if ((k & 0xffffff) == 0) {
            for(int i = 0; i < ind; ++i)
                cout << "  ";
            cout << "Progress round " << round << ": " << setprecision(2) << fixed << (100.*k/0xffffffff) << "%" << endl;
        }
        keys[round-1] = k;
        bool valid = 1;
        int i = 0;
        for (auto& p : ct_pairs[round]) {
            Block l0, r0, l1, r1, x0, x1;
            tie(l0,r0,l1,r1) = p;
            x0 = partial_decrypt(round, l0, r0).first;
            x1 = partial_decrypt(round, l1, r1).first;
            if ((x0 ^ x1) != diffs[round][i]) {valid = 0; break;}
            i++;
        }
        if (valid) {
            for(int i = 0; i < ind; ++i)
                cout << "  ";
            cout << "k[" << (round-1) << "] = " << keys[round-1] << endl;
            if (solve_round(round - 1, ind + 1))
                return true; // remove for exhaustive search
        }
        if (k == 0xffffffff) break;
    }
    return false;
}

int main() {
    int N;
    cin >> N;
    for (int round = 1; round <= 4; ++round) {
        for (int i = 0; i < N; ++i) {
            Block p00, p01, p10, p11, c00, c01, c10, c11;
            p00 = read_block();
            p01 = read_block();
            p10 = read_block();
            p11 = read_block();
            c00 = read_block();
            c01 = read_block();
            c10 = read_block();
            c11 = read_block();
            pt_pairs[round].emplace_back(p00, p01, p10, p11);
            ct_pairs[round].emplace_back(c00, c01, c10, c11);
            diffs[round].push_back(read_block());
        }
    }
    solve_round(4);
}
