module LDAPserver

  # This exception is raised when we need to kill an existing Operation
  # thread because of a received abandonRequest or bindRequest
  class Abandon < Interrupt
  end

  # resultCode constants from RFC 2251 4.1.10; these are all exceptions
  # which can be raised

  class ResultCode < StandardError
  end

  class Success < ResultCode;				def to_i; 0; end; end
  class OperationsError < ResultCode;			def to_i; 1; end; end
  class ProtocolError < ResultCode;			def to_i; 2; end; end
  class TimeLimitExceeded < ResultCode; 		def to_i; 3; end; end
  class SizeLimitExceeded < ResultCode;			def to_i; 4; end; end
  class CompareFalse < ResultCode;			def to_i; 5; end; end
  class CompareTrue < ResultCode;			def to_i; 6; end; end
  class AuthMethodNotSupported < ResultCode;		def to_i; 7; end; end
  class StrongAuthRequired < ResultCode;		def to_i; 8; end; end
  class Referral < ResultCode;				def to_i; 10; end; end
  class AdminLimitExceeded < ResultCode;		def to_i; 11; end; end
  class UnavailableCriticalExtension < ResultCode;	def to_i; 12; end; end
  class ConfidentialityRequired < ResultCode;		def to_i; 13; end; end
  class SaslBindInProgress < ResultCode;		def to_i; 14; end; end
  class NoSuchAttribute < ResultCode;			def to_i; 16; end; end
  class UndefinedAttributeType < ResultCode;		def to_i; 17; end; end
  class InappropriateMatching < ResultCode;		def to_i; 18; end; end
  class ConstraintViolation < ResultCode;		def to_i; 19; end; end
  class AttributeOrValueExists < ResultCode;		def to_i; 20; end; end
  class InvalidAttributeSyntax < ResultCode;		def to_i; 21; end; end
  class NoSuchObject < ResultCode;			def to_i; 32; end; end
  class AliasProblem < ResultCode;			def to_i; 33; end; end
  class InvalidDNSyntax < ResultCode;			def to_i; 34; end; end
  class IsLeaf < ResultCode;				def to_i; 35; end; end
  class AliasDereferencingProblem < ResultCode;		def to_i; 36; end; end
  class InappropriateAuthentication < ResultCode;	def to_i; 48; end; end
  class InvalidCredentials < ResultCode;		def to_i; 49; end; end
  class InsufficientAccessRights < ResultCode;		def to_i; 50; end; end
  class Busy < ResultCode;				def to_i; 51; end; end
  class Unavailable < ResultCode;			def to_i; 52; end; end
  class UnwillingToPerform < ResultCode;		def to_i; 53; end; end
  class LoopDetect < ResultCode;			def to_i; 54; end; end
  class NamingViolation < ResultCode;			def to_i; 64; end; end
  class ObjectClassViolation < ResultCode;		def to_i; 65; end; end
  class NotAllowedOnNonLeaf < ResultCode;		def to_i; 66; end; end
  class NotAllowedOnRDN < ResultCode;			def to_i; 67; end; end
  class EntryAlreadyExists < ResultCode;		def to_i; 68; end; end
  class ObjectClassModsProhibited < ResultCode;		def to_i; 69; end; end
  class AffectsMultipleDSAs < ResultCode;		def to_i; 71; end; end
  class Other < ResultCode;				def to_i; 80; end; end
end
