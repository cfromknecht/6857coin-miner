package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash"
	"log"
	"math/rand"
	"net/http"
	"reflect"
	"runtime"
	"sync"
	"time"
)

func main() {
	for {
		timer := time.NewTimer(15 * time.Second)
		mine(nil)
		select {
		case <-timer.C:
		}
	}
}

func mine(parent []byte) []byte {
	runtime.GC()

	client := http.Client {
		Timeout: time.Second * 5,
	}
	blk := Block{
		Header: new(BlockHeader),
		Block:  "dpchen,lopezv,asnoakes",
	}
	if parent == nil {
		resp, err := client.Get("http://6857coin.csail.mit.edu:8080/next")
		if err != nil {
			log.Println(err)
			return nil
		}
		dec := json.NewDecoder(resp.Body)
		dec.Decode(blk.Header)
	} else {
		blk.Header.ParentId = hex.EncodeToString(parent)
		blk.Header.Difficulty = 38 // no clue how to do this
	}
	blk.Header.Timestamp = uint64(time.Now().UnixNano())
	blk.setRoot()

	log.Println(blk.Header)

	col := newCollider(blk.Header)
	blk.Header.Nonces = col.collide()

	encblk, err := json.Marshal(blk)
	if err != nil {
		log.Println(err)
		return nil
	}

	_, err = client.Post("http://6857coin.csail.mit.edu:8080/add", "application/json", bytes.NewBuffer(encblk))
	if err != nil {
		log.Println(err)
		return nil
	}

	fullHash := blk.Header.fullHash()
	log.Println("block committed", hex.EncodeToString(fullHash))
	return fullHash
}

func mask(difficulty uint64) uint64 {
	return (1 << difficulty) - 1
}

type BlockHeader struct {
	ParentId   string   `json:'parentid'`
	Root       string   `json:'root'`
	Difficulty uint64   `json:'difficulty'`
	Timestamp  uint64   `json:'timestamp'`
	Nonces     []uint64 `json:'nonces'`
	Version    byte     `json:'byte'`
}

type Block struct {
	Header *BlockHeader `json:'header'`
	Block  string       `json:'block'`
}

func (b *Block) setRoot() {
	sum := sha256.Sum256([]byte(b.Block))
	b.Header.Root = hex.EncodeToString(sum[:])
}

func (b *BlockHeader) prefixHash() hash.Hash {
	h := sha256.New()
	parentId, _ := hex.DecodeString(b.ParentId)
	h.Write(parentId)
	root, _ := hex.DecodeString(b.Root)
	h.Write(root)
	binary.Write(h, binary.BigEndian, b.Difficulty)
	binary.Write(h, binary.BigEndian, b.Timestamp)
	return h
}

func (b *BlockHeader) fullHash() []byte {
	h := b.prefixHash()
	buf := make([]byte, 25)
	binary.BigEndian.PutUint64(buf, b.Nonces[0])
	binary.BigEndian.PutUint64(buf[8:], b.Nonces[1])
	binary.BigEndian.PutUint64(buf[16:], b.Nonces[2])
	buf[24] = b.Version
	h.Write(buf)
	return h.Sum(nil)
}

func copyHash(src hash.Hash) hash.Hash {
	typ := reflect.TypeOf(src)
	val := reflect.ValueOf(src)
	if typ.Kind() == reflect.Ptr {
		typ = typ.Elem()
		val = val.Elem()
	}
	elem := reflect.New(typ).Elem()
	elem.Set(val)
	return elem.Addr().Interface().(hash.Hash)
}

func (b *BlockHeader) suffixHash(buf []byte, h hash.Hash, nonce uint64) uint64 {
	hh := copyHash(h)
	binary.BigEndian.PutUint64(buf, nonce)
	buf[8] = b.Version
	hh.Write(buf)
	sum := hh.Sum(buf[:0])
	return binary.BigEndian.Uint64(sum[len(sum)-8:])
}

func (b *BlockHeader) doHash(nonce uint64) {
	h := sha256.New()
	parentId, _ := hex.DecodeString(b.ParentId)
	h.Write(parentId)
	root, _ := hex.DecodeString(b.Root)
	h.Write(root)
	binary.Write(h, binary.BigEndian, b.Difficulty)
	binary.Write(h, binary.BigEndian, b.Timestamp)

	buf := make([]byte, 9)
	binary.BigEndian.PutUint64(buf, nonce)
	buf[8] = b.Version
	h.Write(buf)

	log.Println(hex.EncodeToString(h.Sum(nil)))
}

type Entry struct {
	nonceA uint64
	nonceB uint64
	sum    uint64
}

type Collider struct {
	tableMask uint64
	entries   []Entry
	locks     []sync.Mutex
	header    *BlockHeader
}

func newCollider(h *BlockHeader) *Collider {
	size := (1 << (h.Difficulty*2/3))
	if size > (1 << 27) {
		size = 1 << 27
	}
	log.Println("collider allocating", size)
	return &Collider{
		tableMask: uint64(size - 1),
		entries:   make([]Entry, size),
		locks:     make([]sync.Mutex, 256),
		header:    h,
	}
}

func (c *Collider) insert(sum uint64, nonce uint64) (nonces []uint64) {
	bucket := sum & c.tableMask
	lock := sum & 255
	c.locks[lock].Lock()
	entry := &c.entries[bucket]
	if entry.nonceA == 0 {
		entry.nonceA = nonce
		entry.sum = sum
		c.locks[lock].Unlock()
		return
	}
	if entry.sum != sum {
		c.locks[lock].Unlock()
		return
	}
	if entry.nonceB == 0 {
		entry.nonceB = nonce
	} else {
		nonces = []uint64{entry.nonceA, entry.nonceB, nonce}
	}
	c.locks[lock].Unlock()
	return
}

func (c *Collider) collideWorker(res chan []uint64, stop chan bool, progress chan uint64, wg *sync.WaitGroup) {
	defer wg.Done()
	origH := c.header.prefixHash()
	nonce := uint64(rand.Int63())
	m := mask(c.header.Difficulty)
	buf := make([]byte, 128)
	for i := 0; ; i++ {
		sum := c.header.suffixHash(buf, origH, nonce) & m
		nonces := c.insert(sum, nonce)
		if nonces != nil {
			log.Println("found sum", sum, "nonces", nonces)
			select {
			case res <- nonces:
			case <-stop:
			}
			return
		}
		nonce++

		if i > 0 && i%100000 == 0 {
			select {
			case progress <- 100000:
			case <-stop:
				return
			}
		}
		if i&65535 == 0 {
			select {
			case <-stop:
				return
			default:
			}
		}
	}
}

func (c *Collider) collide() (nonces []uint64) {
	workers := 12

	log.Println("starting workers")
	res := make(chan []uint64)
	progress := make(chan uint64)
	wg := sync.WaitGroup{}
	defer wg.Wait()
	stop := make(chan bool)
	defer close(stop)
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go c.collideWorker(res, stop, progress, &wg)
	}

	count := uint64(0)
	for {
		select {
		case nonces = <-res:
			return
		case <-stop:
			log.Println("collider stopped")
			return nil
		case incr := <-progress:
			count += incr
			if count % 1000000 == 0 {
				log.Println("tried", count, "nonces")
			}
		}
	}
}
