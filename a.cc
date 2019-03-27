#include <atomic>
#include <stdio.h>
#include <thread>
#include <vector>
#include <memory>
#include <string.h>
#include <random>
#include <unistd.h>
#include <condition_variable>
#include <mutex>

// Incudes from https://github.com/tromp/cuckoo
#include "../crypto/blake2.h"
#include "../crypto/siphash.hpp"
#include "../crypto/siphashxN.h"

using uint16 = uint16_t;
using uint32 = uint32_t;
using uint64 = uint64_t;
constexpr uint32 kEdgeBits = 31;
constexpr uint32 nEdges = 1 << kEdgeBits;

constexpr uint32 HEADERLEN = 80;

void setheader(const char *header, uint32 headerlen, siphash_keys *keys) {
  char hdrkey[32];
  blake2b((void *)hdrkey, sizeof(hdrkey), (const void *)header, headerlen, 0, 0);
  keys->setkeys(hdrkey);
}

void setheadernonce(char* const headernonce, uint32 len, uint32 nonce, siphash_keys *keys) {
  uint32 n = htole32(nonce);
  memcpy(headernonce + len - 4, &n, sizeof(n));
  setheader(headernonce, len, keys);
}
 
template<int nbits>
class Encoder {
 public:
  void Add(uint32 x) {
    if (next_ == limit_) {
      blocks_.emplace_back(new uint32[kBlockSize]);
      next_ = blocks_.back().get();
      limit_ = next_ + kBlockSize;
    }
    uint32 dif = 2u * (x - prev_) - 1u;
    prev_ = x;
    int bits = std::max(32 - __builtin_clz(dif), nbits);
    if (bits > nbits) {
      dif &= (uint32{1} << (bits - 1)) - 1;
      pending_ |= uint64{dif} << (m_ + bits - nbits);
      bits += bits - 1 - nbits;
    } else {
      pending_ |= uint64{dif} << m_;
    }
    m_ += bits;
    if (m_ >= 32) {
      *next_ = pending_;
      ++next_;
      pending_ >>= 32;
      m_ -= 32;
    }
    ++n_;
  }

  void Finalize() {
    if (m_ != 0 && next_ == limit_) {
      blocks_.emplace_back(new uint32[2]);
      blocks_.back().get()[0] = pending_;
      blocks_.back().get()[1] = 0;
    } else {
      if (m_ != 0) {
        *next_ = pending_;
        ++next_;        
      }
      if (next_ == limit_) {
        blocks_.emplace_back(new uint32[1]);
        blocks_.back().get()[0] = 0;
      } else {
        *next_ = 0;
        ++next_;
        uint32 sz = next_ - blocks_.back().get();
        std::unique_ptr<uint32[]> arr(new uint32[sz]);
        memcpy(arr.get(), blocks_.back().get(), sz * sizeof(uint32));
        blocks_.back() = std::move(arr);
      }
    }
  }

 private:
  static constexpr uint32 kBlockSize = 2048;
  uint32 prev_ = ~uint32{0};
  uint32 n_ = 0;
  uint32 m_ = 0;
  uint64 pending_ = 0;  
  uint32* next_ = nullptr;
  uint32* limit_ = nullptr;
  std::vector<std::unique_ptr<uint32[]>> blocks_;
  template<int>
  friend class Decoder;
};

template<int nbits>
class Decoder {
 public:
  Decoder() = default;
  Decoder(Decoder&&) = default;
  Decoder& operator=(Decoder&&) = default;
  Decoder(Encoder<nbits>&& encoder) : blocks_(std::move(encoder.blocks_)), i_(1), n_(encoder.n_) {
    next_ = blocks_[0].get();
    limit_ = next_ + Encoder<nbits>::kBlockSize;
    pending_ |= uint64{*next_} << m_;
    ++next_;
    m_ += 32u;
  }
  uint32 Size() const { return n_; }
  uint32 Get() {
    --n_;
    if (m_ <= 32u) {
      if (next_ == limit_) {
        blocks_[i_ - 1].reset();
        next_ = blocks_[i_].get();
        limit_ = next_ + Encoder<nbits>::kBlockSize;
        ++i_;
      }
      pending_ |= uint64{*next_} << m_;
      ++next_;
      m_ += 32u;
    }
    int bits = __builtin_ctz(pending_);
    int dif;
    if (bits == 0) {
      dif = (pending_) & ((uint32{1} << nbits) - 1u);
      m_ -= nbits;
      pending_ >>= nbits;
    } else {
      uint32 rbits = bits + nbits - 1;
      dif = (pending_ >> bits) & ((uint32{1} << rbits) - 1u);
      dif += uint32{1} << rbits;
      m_ -= rbits + bits;
      pending_ >>= rbits + bits;
    }
    return prev_ = prev_ + 1u + (dif >> 1);
  }
  size_t NumBlocks() const { return blocks_.size(); }
 private:
  std::vector<std::unique_ptr<uint32[]>> blocks_;
  uint32* next_ = nullptr;
  uint32* limit_ = nullptr;
  uint32 i_ = 0;
  uint32 n_ = 0;
  uint32 prev_ = ~uint32{0};
  uint32 m_ = 0;
  uint64 pending_ = 0;  
};

template<typename VD>
void report_size(const VD& vd) {
  size_t sum = 0;
  size_t sum2 = 0;
  for (const auto& d : vd) {
    sum += d.NumBlocks();
    sum2 += d.Size();
  }
  printf("Memory used: %ld Num edges: %ld (%.6lf%%)\n", sum * (8 << 10), sum2, sum2 * 100.0 / nEdges);
}

constexpr int D1 = 7;
constexpr int D2 = 13;
constexpr int D3 = 14;
struct Ctx {
  Ctx(int nthreads) : d1(nthreads) {}
  siphash_keys sipkeys;
  std::vector<std::vector<Decoder<D1>>> d1;
  std::atomic<int> next = ATOMIC_VAR_INIT(0);
  std::vector<Decoder<D2>> d2;
  std::vector<Decoder<D3>> d3;
  std::mutex mu;
  int done = 0;
  int phase = 0;
  std::condition_variable cv;
};

int main(int argc, char** argv) {
  int nthreads = 1;
  if (argc == 2) {
    if (sscanf(argv[1], "%d", &nthreads) != 1) {
      printf("Can't parse %s\n", argv[1]);
    }
    if (nthreads < 1 || nthreads > (1<<16)) {
      printf("Invalid number of threads %d", nthreads);
    }
  }
  printf("Num threads: %d\n", nthreads);
  
  char header[HEADERLEN];
  memset(header, 0, HEADERLEN);
  uint32 nonce = 0;
  std::unique_ptr<Ctx> ctx(new Ctx(nthreads));
  setheadernonce(header, sizeof(header), nonce, &ctx->sipkeys);
  std::vector<std::thread> threads;
  
  auto op = [nthreads](uint32 idx, Ctx* ctx){
    alignas(32) auto lsipkeys = ctx->sipkeys;
    alignas(32) uint64 edges[8];
    alignas(32) uint64 hashes[8];
    std::vector<Encoder<D1>> e(128);
    uint32 start = (uint64{idx} * nEdges / nthreads) & ~7u;
    uint32 end = (uint64{idx + 1} * nEdges / nthreads) & ~7u;
    for (uint32 i = start; i < end; i += 8) {
      for (uint32 j = 0; j < 8; ++j) {
        edges[j] = (i + j) << 1;
      }
      siphash24x8(&lsipkeys, edges, hashes);
      for (uint32 j = 0; j < 8; ++j) {
        uint32 g = (hashes[j] >> (kEdgeBits - 7)) & 127;
        e[g].Add(i + j);
      }
    }
    for (int i = 0; i < 128; ++i) {
      e[i].Finalize();
      ctx->d1[idx].emplace_back(std::move(e[i]));
    }
    
    {
      std::unique_lock<std::mutex> lk(ctx->mu);
      ++ctx->done;
      if (ctx->done < nthreads) {
        ctx->cv.wait(lk, [&]{ return ctx->phase == 1; });
      } else {
        ctx->d2.resize(8192);
        ctx->phase = 1;
        ctx->done = 0;
        ctx->cv.notify_all();
      }
    }
    
    while (true) {
      int idx = ctx->next.fetch_add(1, std::memory_order_relaxed);
      if (idx >= 128) break;
      std::vector<Encoder<D2>> e(64);
      for (int i = 0; i < nthreads; ++i) {
        auto d = std::move(ctx->d1[i][idx]);
        while (d.Size()) {
          edges[0] = d.Get() << 1;
          uint32 j;
          for (j = 1; d.Size() && j < 8; ++j) {
            edges[j] = d.Get() << 1;
          }
          siphash24x8(&lsipkeys, edges, hashes);
          for (uint32 k = 0; k < j; ++k) {
            uint32 g = (hashes[k] >> (kEdgeBits - 13)) & 63;
            e[g].Add(edges[k] >> 1);
          }
        }
      }
      for (int i = 0; i < 64; ++i) {
        e[i].Finalize();
        ctx->d2[idx * 64 + i] = Decoder<D2>(std::move(e[i]));
      }
    }
    {
      std::unique_lock<std::mutex> lk(ctx->mu);
      ++ctx->done;
      if (ctx->done < nthreads) {
        ctx->cv.wait(lk, [&]{ return ctx->phase == 2; });
      } else {
        ctx->d1.clear();
        ctx->d3.resize(8192);
        ctx->phase = 2;
        ctx->next.store(0, std::memory_order_relaxed);
        ctx->done = 0;
        ctx->cv.notify_all();
        printf("Buckets before trimming:\n");
        report_size(ctx->d2);
      }
    }
    {
      std::vector<std::pair<uint32, uint32>> dec;
      dec.reserve(264191);
      std::array<uint32, 8192> bits;
      while (true) {
        int idx = ctx->next.fetch_add(1, std::memory_order_relaxed);
        if (idx >= 8192) break;
        dec.clear();
        memset(bits.data(), 0, bits.size() * 4);
        Encoder<D3> enc;
        auto d = std::move(ctx->d2[idx]);
        while (d.Size()) {
          edges[0] = d.Get() << 1;
          uint32 j;
          for (j = 1; d.Size() && j < 8; ++j) {
            edges[j] = d.Get() << 1;
          }
          siphash24x8(&lsipkeys, edges, hashes);
          for (uint32 k = 0; k < j; ++k) {
            uint32 g = hashes[k] & 262143;
            dec.emplace_back(edges[k] >> 1, g ^ 1);
            bits[g >> 5] |= 1u << (g & 31);
          }
        }
        for (auto x : dec) {
          uint32 g = x.second;
          if (bits[g >> 5] & (1u << (g & 31))) {
            enc.Add(x.first);
          }
        }
        enc.Finalize();
        ctx->d3[idx] = std::move(enc);
      }
    }
    {
      std::unique_lock<std::mutex> lk(ctx->mu);
      ++ctx->done;
      if (ctx->done < nthreads) {
        ctx->cv.wait(lk, [&]{ return ctx->phase == 3; });
      } else {
        ctx->d2.clear();
        ctx->phase = 3;
        ctx->next.store(0, std::memory_order_relaxed);
        ctx->done = 0;
        ctx->cv.notify_all();
        printf("Buckets after trimming:\n");
        report_size(ctx->d3);
      }
    }
  };
  
  for (int i = 0; i + 1 < nthreads; ++i) threads.emplace_back(op, i, ctx.get());
  op(nthreads - 1, ctx.get());
  for (auto& t : threads) t.join();
}
