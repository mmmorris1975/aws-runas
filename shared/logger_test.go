package shared

// get some cheap coverage wins

func ExampleDefaultLogger_Debugf() {
	new(DefaultLogger).Debugf("")
	// Output:
	//
}

func ExampleDefaultLogger_Errorf() {
	new(DefaultLogger).Errorf("")
	// Output:
	//
}

func ExampleDefaultLogger_Infof() {
	new(DefaultLogger).Infof("")
	// Output:
	//
}

func ExampleDefaultLogger_Warningf() {
	new(DefaultLogger).Warningf("")
	// Output:
	//
}
