package iden3comm

import (
	"context"
	"github.com/pkg/errors"
	"sync"
)

// Service is an interface for IDEN3Comm messaging protocol
type Service interface {
	Name() string
	AcceptedMessages()  []ProtocolMessage
	Handle(ctx context.Context, msg Iden3Message) (Iden3Message, error)
}

// Package messaging  maintains the list of registered message services and message types.
const (
	errAlreadyRegistered = "registration failed, service for protocol message type `%s` is already assigned"
	errNeverRegistered   = "failed to unregister, unable to find registered message service with name `%s`"
)

// NewRegistrar returns new message registrar instance.
func NewRegistrar() *Registrar {
	return &Registrar{services: make(map[ProtocolMessage]Service)}
}

// Registrar is message service provider that allows to register / unregister services
type Registrar struct {
	services map[ProtocolMessage]Service
	lock     sync.RWMutex
}

// Services returns list of message services registered to this handler.
func (m *Registrar) Services() map[ProtocolMessage]Service {
	m.lock.RLock()
	defer m.lock.RUnlock()

	return m.services
}

// Register registers given message services to this handle, in case of duplication in returns an error
func (m *Registrar) Register(msgServices ...Service) error {
	if len(msgServices) == 0 {
		return nil
	}

	m.lock.Lock()
	defer m.lock.Unlock()

	for _, s := range msgServices {
		for _, msgType := range s.AcceptedMessages() {
			_, ok := m.services[msgType]
			if ok {
				return errors.Errorf(errAlreadyRegistered, msgType)
			}
			m.services[msgType] = s
		}
	}
	return nil
}

// Unregister unregisters message service with given name from this message handler, returns error if given message service doesn't exist.
func (m *Registrar) Unregister(name string) error {
	m.lock.Lock()
	defer m.lock.Unlock()

	var msgTypes []ProtocolMessage

	for msgType, svc := range m.services {
		if svc.Name() == name {
			msgTypes = append(msgTypes, msgType)
		}
	}

	if len(msgTypes) == 0 {
		return errors.Errorf(errNeverRegistered, name)
	}

	for _, msgType := range msgTypes {
		delete(m.services, msgType)
	}

	return nil
}
