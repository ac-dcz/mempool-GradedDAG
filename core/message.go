package core

import (
	"bytes"
	"encoding/gob"
	"gradeddag/crypto"
	"gradeddag/pool"
	"reflect"
	"strconv"
)

type ConsensusMessage interface {
	MsgType() int
	Hash() crypto.Digest
}

type Block struct {
	Author    NodeID
	Round     int
	Batch     pool.Batch
	Reference map[crypto.Digest]NodeID
}

func (b *Block) Encode() ([]byte, error) {
	buf := bytes.NewBuffer(nil)
	if err := gob.NewEncoder(buf).Encode(b); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func (b *Block) Decode(data []byte) error {
	buf := bytes.NewBuffer(data)
	if err := gob.NewDecoder(buf).Decode(b); err != nil {
		return err
	}
	return nil
}

func (b *Block) Hash() crypto.Digest {

	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(b.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(b.Round), 2))
	for _, tx := range b.Batch.Txs {
		hasher.Add(tx)
	}
	// for d, id := range b.Reference {
	// 	hasher.Add(d[:])
	// 	hasher.Add(strconv.AppendInt(nil, int64(id), 2))
	// }

	return hasher.Sum256(nil)
}

// ProposeMsg
type GRBCProposeMsg struct {
	Author    NodeID
	Round     int
	B         *Block
	Signature crypto.Signature
}

func NewGRBCProposeMsg(
	Author NodeID,
	Round int,
	B *Block,
	sigService *crypto.SigService,
) (*GRBCProposeMsg, error) {

	msg := &GRBCProposeMsg{
		Author: Author,
		Round:  Round,
		B:      B,
	}

	if sig, err := sigService.RequestSignature(msg.Hash()); err != nil {
		return nil, err
	} else {
		msg.Signature = sig
		return msg, nil
	}
}

func (msg *GRBCProposeMsg) Verify(committee Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *GRBCProposeMsg) Hash() crypto.Digest {

	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.Round), 2))
	digest := msg.B.Hash()
	hasher.Add(digest[:])
	return hasher.Sum256(nil)
}

func (msg *GRBCProposeMsg) MsgType() int {
	return GRBCProposeType
}

// EchoMsg
type EchoMsg struct {
	Author    NodeID
	Proposer  NodeID
	BlockHash crypto.Digest
	Round     int
	Signature crypto.Signature
}

func NewEchoMsg(
	Author NodeID,
	Proposer NodeID,
	BlockHash crypto.Digest,
	Round int,
	sigService *crypto.SigService,
) (*EchoMsg, error) {
	msg := &EchoMsg{
		Author:    Author,
		Proposer:  Proposer,
		BlockHash: BlockHash,
		Round:     Round,
	}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *EchoMsg) Verify(committee Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *EchoMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.Proposer), 2))
	hasher.Add(msg.BlockHash[:])
	hasher.Add(strconv.AppendInt(nil, int64(msg.Round), 2))
	return hasher.Sum256(nil)
}

func (msg *EchoMsg) MsgType() int {
	return EchoType
}

// ReadyMsg
type ReadyMsg struct {
	Author    NodeID
	Proposer  NodeID
	BlockHash crypto.Digest
	Round     int
	Signature crypto.Signature
}

func NewReadyMsg(
	Author NodeID,
	Proposer NodeID,
	BlockHash crypto.Digest,
	Round int,
	sigService *crypto.SigService,
) (*ReadyMsg, error) {
	msg := &ReadyMsg{
		Author:    Author,
		Proposer:  Proposer,
		BlockHash: BlockHash,
		Round:     Round,
	}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *ReadyMsg) Verify(committee Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *ReadyMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.Proposer), 2))
	hasher.Add(msg.BlockHash[:])
	hasher.Add(strconv.AppendInt(nil, int64(msg.Round), 2))
	return hasher.Sum256(nil)
}

func (msg *ReadyMsg) MsgType() int {
	return ReadyType
}

// CBCProposeMsg
type CBCProposeMsg struct {
	Author    NodeID
	Round     int
	B         *Block
	Signature crypto.Signature
}

func NewCBCProposeMsg(
	Author NodeID,
	Round int,
	B *Block,
	sigService *crypto.SigService,
) (*CBCProposeMsg, error) {

	msg := &CBCProposeMsg{
		Author: Author,
		Round:  Round,
		B:      B,
	}

	if sig, err := sigService.RequestSignature(msg.Hash()); err != nil {
		return nil, err
	} else {
		msg.Signature = sig
		return msg, nil
	}
}

func (msg *CBCProposeMsg) Verify(committee Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *CBCProposeMsg) Hash() crypto.Digest {

	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.Round), 2))
	digest := msg.B.Hash()
	hasher.Add(digest[:])
	return hasher.Sum256(nil)
}

func (msg *CBCProposeMsg) MsgType() int {
	return CBCProposeType
}

type CBCVoteMsg struct {
	Author    NodeID
	Proposer  NodeID
	BlockHash crypto.Digest
	Round     int
	Signature crypto.Signature
}

func NewCBCVoteMsg(Author NodeID, B *Block, sigService *crypto.SigService) (*CBCVoteMsg, error) {
	vote := &CBCVoteMsg{
		Author:    Author,
		Proposer:  B.Author,
		BlockHash: B.Hash(),
		Round:     B.Round,
	}
	vote.Signature, _ = sigService.RequestSignature(vote.Hash())
	return vote, nil
}

func (v *CBCVoteMsg) Verify(committee Committee) bool {
	pub := committee.Name(v.Author)
	return v.Signature.Verify(pub, v.Hash())
}

func (v *CBCVoteMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(v.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Proposer), 2))
	hasher.Add(strconv.AppendInt(nil, int64(v.Round), 2))
	hasher.Add(v.BlockHash[:])
	return hasher.Sum256(nil)
}

func (v *CBCVoteMsg) MsgType() int {
	return CBCVoteType
}

// ElectMsg
type ElectMsg struct {
	Author   NodeID
	Round    int
	SigShare crypto.SignatureShare
}

func NewElectMsg(Author NodeID, Round int, sigService *crypto.SigService) (*ElectMsg, error) {
	msg := &ElectMsg{
		Author: Author,
		Round:  Round,
	}
	share, err := sigService.RequestTsSugnature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.SigShare = share

	return msg, nil
}

func (msg *ElectMsg) Verify() bool {
	return msg.SigShare.Verify(msg.Hash())
}

func (msg *ElectMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	// hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.Round), 2))
	return hasher.Sum256(nil)
}

func (msg *ElectMsg) MsgType() int {
	return ElectType
}

// RequestBlock
type RequestBlockMsg struct {
	Author    NodeID
	MissBlock []crypto.Digest
	Signature crypto.Signature
	ReqID     int
	Ts        int64
}

func NewRequestBlock(
	Author NodeID,
	MissBlock []crypto.Digest,
	ReqID int,
	Ts int64,
	sigService *crypto.SigService,
) (*RequestBlockMsg, error) {
	msg := &RequestBlockMsg{
		Author:    Author,
		MissBlock: MissBlock,
		ReqID:     ReqID,
		Ts:        Ts,
	}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *RequestBlockMsg) Verify(committee Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *RequestBlockMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.ReqID), 2))
	for _, d := range msg.MissBlock {
		hasher.Add(d[:])
	}
	return hasher.Sum256(nil)
}

func (msg *RequestBlockMsg) MsgType() int {
	return RequestBlockType
}

// ReplyBlockMsg
type ReplyBlockMsg struct {
	Author    NodeID
	Blocks    []*Block
	ReqID     int
	Signature crypto.Signature
}

func NewReplyBlockMsg(Author NodeID, B []*Block, ReqID int, sigService *crypto.SigService) (*ReplyBlockMsg, error) {
	msg := &ReplyBlockMsg{
		Author: Author,
		Blocks: B,
		ReqID:  ReqID,
	}
	sig, err := sigService.RequestSignature(msg.Hash())
	if err != nil {
		return nil, err
	}
	msg.Signature = sig
	return msg, nil
}

func (msg *ReplyBlockMsg) Verify(committee Committee) bool {
	return msg.Signature.Verify(committee.Name(msg.Author), msg.Hash())
}

func (msg *ReplyBlockMsg) Hash() crypto.Digest {
	hasher := crypto.NewHasher()
	hasher.Add(strconv.AppendInt(nil, int64(msg.Author), 2))
	hasher.Add(strconv.AppendInt(nil, int64(msg.ReqID), 2))
	return hasher.Sum256(nil)
}

func (msg *ReplyBlockMsg) MsgType() int {
	return ReplyBlockType
}

type LoopBackMsg struct {
	BlockHash crypto.Digest
}

func (msg *LoopBackMsg) Hash() crypto.Digest {
	return crypto.NewHasher().Sum256(msg.BlockHash[:])
}

func (msg *LoopBackMsg) MsgType() int {
	return LoopBackType
}

const (
	GRBCProposeType int = iota
	EchoType
	ReadyType
	ElectType
	CBCProposeType
	CBCVoteType
	RequestBlockType
	ReplyBlockType
	LoopBackType
	TotalNums
)

var DefaultMsgTypes = map[int]reflect.Type{
	GRBCProposeType:  reflect.TypeOf(GRBCProposeMsg{}),
	EchoType:         reflect.TypeOf(EchoMsg{}),
	ReadyType:        reflect.TypeOf(ReadyMsg{}),
	ElectType:        reflect.TypeOf(ElectMsg{}),
	CBCProposeType:   reflect.TypeOf(CBCProposeMsg{}),
	CBCVoteType:      reflect.TypeOf(CBCVoteMsg{}),
	RequestBlockType: reflect.TypeOf(RequestBlockMsg{}),
	ReplyBlockType:   reflect.TypeOf(ReplyBlockMsg{}),
	LoopBackType:     reflect.TypeOf(LoopBackMsg{}),
}
