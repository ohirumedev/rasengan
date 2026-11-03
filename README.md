# rasengan API



 
router.POST("/register", register). - self explanatory
	router.POST("/login", login) - same
	router.POST("/logout", logout) - same
	router.GET("/protected", protected) - idc why this is here but also self explanatory
	router.GET("/me", getMe). - will be used in frontend alot :) but also pretty self explanatory
	router.POST("/location/create", createLocation) - locations API. if you create a location with the same name it will reject cuz only 1 location can use the same name.
	router.POST("/location/search", SearchLocation) - search API and you can also control if you save 
