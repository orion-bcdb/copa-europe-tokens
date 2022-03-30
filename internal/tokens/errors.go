package tokens

type ErrExist struct {
	ErrMsg string
}

func (e *ErrExist) Error() string {
	return e.ErrMsg
}


type ErrInvalid struct {
	ErrMsg string
}

func (e *ErrInvalid) Error() string {
	return e.ErrMsg
}


type ErrNotFound struct {
	ErrMsg string
}

func (e *ErrNotFound) Error() string {
	return e.ErrMsg
}
