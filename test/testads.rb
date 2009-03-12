require 'test/unit'
require 'authenticate_ads'

class TestAds < Test::Unit::TestCase
  #Active Directory: Try to authenticate with valid user credentials
  def test_ads_user_authenticate_successful
    ads = AuthenticateAds.new('Administrator','realpw', 'realdomaincontroller', 'realdomain', 'realtld')
    assert(ads.valid_user?, 'User was unable to authenticate successfully.')
  end

  #Active Directory: Try to authenticate with valid user credentials (incl. group)
  def test_ads_user_and_group_authenticate_successful
    ads = AuthenticateAds.new('Administrator','realpw', 'realdomaincontroller', 'realdomain', 'realtld')
    assert(ads.valid_user_and_in_group?('Administrators'), 'User was unable to authenticate successfully.')
  end

  def test_ads_user_and_group_authenticate_fail
    ads = AuthenticateAds.new('Administrator','realpw', 'realdomaincontroller', 'realdomain', 'realtld')
    assert(!ads.valid_user_and_in_group?('somegroup'), "User was able to authenticate successfully (shouldn't be the case).")
  end

   #Active Directory: Try to authenticate with non-existent user credentials.
  def test_ads_user_authenticate_fail
    ads = AuthenticateAds.new('someuser','somepw', 'realdomaincontroller', 'realdomain', 'realtld')
    assert(!ads.valid_user?, "User was able to authenticate successfully (shouldn't be the case).")
  end

  #Active Directory: Try to connect to a non-existent domain controller in a non-existent domain.
  def test_ads_no_valid_connection
    assert_raise Net::LDAP::LdapError do
      ads = AuthenticateAds.new('someuser','somepw', 'somedomaincontroller', 'somedomain', 'tld')
      puts ads.valid_user?
    end
  end
end
