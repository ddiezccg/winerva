@{
    # The credentials for the local administrator account that will be created
    # on the target machine.
    LocalAdmin = @{
        # The local administrator account (login) name.
        #
        # @type System.String
        # @required
        #
        Username = "testadmin"

        # The local administrator account (login) password. THE PASSWORD MUST BE
        # STORED AS PLAIN TEXT IN THIS FILE.
        #
        # @type System.String
        # @required
        #
        Password = "This is the Windows password!"

        # The description for the local administrator account. The value can be
        # zero-length, but not null.
        #
        # @type System.String
        # @required
        #
        Description = "The local admin account for remote administration."
    }
}