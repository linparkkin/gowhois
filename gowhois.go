package main

import (
    "github.com/likexian/whois"
	"github.com/likexian/whois-parser"
	"fmt"
	"flag"
	"time"
	"log"
	"os"
	"bufio"
	"sync"
)

var inp *string //input path
var inpFile *string //input config path
var wg sync.WaitGroup //waitgroup for goroutines
var retries *int //number of retries
var threads *int //number of retries
var PrintIfError *bool
var Parsed *bool


func init() {
	inp = flag.String("input","","Domain/IP/AS to analyse")
	inpFile = flag.String("input-list","","File containing a list of domain/IP/AS to analyse")
	retries = flag.Int("retry",5,"Number of retries if fail.")
	threads = flag.Int("threads",1,"Number of threads.")
	PrintIfError = flag.Bool("blind",true,"Print raw whois info even if an error during parsing occurs.")
	Parsed = flag.Bool("parse",true,"Set to true if you want parsed results.")
	flag.Usage = func() {
		fmt.Println("GOWHOIS, query multiple domains at once.")
		fmt.Println("----------------------------")
		fmt.Println("Usage:")
		flag.PrintDefaults()
	}
	flag.Parse()
}

func main() {
	start := time.Now()
	goroutines := make(chan int, *threads)
	if *inp!=""{
		log.Println("INFO - Analysis started")
		wg.Add(1)
		goroutines <- 1
		go doWhois(*inp,&wg, goroutines)
		wg.Wait()
		log.Printf("INFO - Analysis ended in %v",time.Since(start))
	} else if *inpFile!=""{
		log.Println("INFO - Analysis started")
		file, err := os.Open(*inpFile)
		if err != nil {
			log.Printf("ERROR - %v", err)
			return
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()
			wg.Add(1)
			goroutines <- 1
			go doWhois(line,&wg, goroutines)
		}
		wg.Wait()
		log.Printf("INFO - Analysis ended in %v",time.Since(start))
	} else {
		flag.Usage()
	}

}

func doWhois(input string, wg *sync.WaitGroup,goroutines chan int){
	defer func() {
		<- goroutines
		wg.Done()
	}()
	counter := 0
	for(counter < *retries){
		result, err := whois.Whois(input)
		if (err == nil) && *Parsed{
			counter = *retries
			result, err := whoisparser.Parse(result)
			if err == nil {
				fmt.Printf("DOMAIN: %v\n",input)
				// Print the domain status
				if result.Domain != nil {
					fmt.Printf("STATUS: %v\n",result.Domain.Status)
				// Print the domain created date
					fmt.Printf("CREATION DATE: %v\n",result.Domain.CreatedDate)
					fmt.Printf("UPDATED DATE: %v\n",result.Domain.UpdatedDate)
				// Print the domain expiration date
					fmt.Printf("EXPIRATION DATE: %v\n",result.Domain.ExpirationDate)
				}
				if result.Registrar != nil {
				// Print the registrar name
					fmt.Printf("REGISTRAR: %v\n",result.Registrar.Name)
				}
				if result.Registrant != nil {
					// Print the registrar name
						fmt.Printf("REGISTRAR: %v\n",result.Registrar.Name)
					// Print the registrant name
						fmt.Printf("REGISTRANT: %v\n",result.Registrant.Name)
					}
				fmt.Printf("\n")
			} else if (err!=nil && result.Domain!=nil) {
				fmt.Printf("DOMAIN: %v\n",input)
				// Print the domain status
				if result.Domain != nil {
					fmt.Printf("STATUS: %v\n",result.Domain.Status)
				// Print the domain created date
					fmt.Printf("CREATION DATE: %v\n",result.Domain.CreatedDate)
					fmt.Printf("UPDATED DATE: %v\n",result.Domain.UpdatedDate)
				// Print the domain expiration date
					fmt.Printf("EXPIRATION DATE: %v\n",result.Domain.ExpirationDate)
				}
				if result.Registrar != nil {
				// Print the registrar name
					fmt.Printf("REGISTRAR: %v\n",result.Registrar.Name)
				}
				if result.Registrant != nil {
					// Print the registrar name
						fmt.Printf("REGISTRAR: %v\n",result.Registrar.Name)
					// Print the registrant name
						fmt.Printf("REGISTRANT: %v\n",result.Registrant.Name)
					}
				fmt.Printf("ERROR: %v\n\n",err)
			} 
		} else if (err == nil) && !*Parsed{
			counter = *retries
			fmt.Printf("DOMAIN: %v\n",input)
			fmt.Printf("%v\n\n",result)
		} else {
			counter++
			if counter==*retries{
				fmt.Printf("ERROR: %v\n",input)
				if result !="" && *PrintIfError{
					fmt.Printf("%v",result)
				}
				fmt.Printf("ERROR: %v\n\n",err)
			}
		}
	} 
}