require 'test/unit'
require 'authenticate_ldap'

class TestLdap < Test::Unit::TestCase
  #OpenLDAP: Try to authenticate with valid user credentials
  def test_ldap_user_authenticate_successful
    ldap = AuthenticateLdap.new('jqpublic','wombat','people', 'denver', 'mycompany', 'com')
    assert(ldap.valid_user?, 'User was unable to authenticate successfully.')
  end

  #OpenLDAP: Try to authenticate with valid user credentials (incl. group)
  def test_ldap_user_and_group_authenticate_successful
    ldap = AuthenticateLdap.new('jqpublic','wombat','people', 'denver', 'mycompany', 'com')
    assert(ldap.valid_user_and_in_group?("staff", "groups"), 'User was unable to authenticate successfully.')
  end

  #OpenLDAP: Try to authenticate with valid user credentials and a non-existent group
  def test_ldap_user_and_group_authenticate_fail
    ldap = AuthenticateLdap.new('jqpublic','wombat','people', 'denver', 'mycompany', 'com')
    assert(!ldap.valid_user_and_in_group?("somegroup", "groups"), "User was able to authenticate successfully (shouldn't be the case).")
  end

  #OpenLDAP: Try to authenticate with non-existent user credentials.
  def test_ldap_user_authenticate_fail
    ldap = AuthenticateLdap.new('someuser','somepw','people', 'denver', 'mycompany', 'com')
    assert(!ldap.valid_user?, "User was able to authenticate successfully (shouldn't be the case).")
  end

  #OpenLDAP: Try to connect to a non-existent ldap server
  def test_ldap_no_valid_connection
    assert_raise Net::LDAP::LdapError do
      ldap = AuthenticateLdap.new('someuser','somepw','someou', 'some_host', 'dc', 'tld')
      puts ldap.valid_user?
    end
  end
end
