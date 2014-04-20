/**
 * Data representations for the UFP Identity API.
 * <h3>Result</h3>
 * A few notes about the attributes of a Result object. Depending on the type of Context the Result is part of, the value of the Result object may be
 * one of SUCCESS, FAILURE, CONTINUE or RESET with a corresponding message indicating some additional textual information. The message, along with the
 * numeric code indicating the reason for the Result's value, are used to programmatically determine next steps e.g. for preAuthenticate, a Result value
 * of FAILURE with code 4 and message "User not found" may lead to a registration flow. Special care must be taken to not propagate failures to the user.
 * For security purposes, not indicating what actually went wrong to the user prevents malicious users from knowing too much about the system.
 * <p>
 * A result object contains two other attributes. For the vast majority of sites the confidence and level can be ignored. The confidence reflects the
 * UFP Identity's confidence in the authentication. For instance if the user has entered the correct password but risk analysis has determined a high risk,
 * the confidence may be lowered. The level indicates an aggregate level of strength of the authentication. A simple password that has been used for some
 * time may have a low level. A two-factor authentication token may have higher level.
 *
 * <h3>FormElement and DisplayItem</h3>
 * FormElement and DisplayItem are distinguished from each other specifically for known vs. unknown form inputs to be displayed to the user. It is presumed that
 * the details of enrollment are well known to any specific integration. Calling {@link com.ufp.identity4j.provider.IdentityServiceProvider#preEnroll} for a list
 * of FormElement is not strictly necessary. The details of authentication are not known {@link com.ufp.identity4j.provider.IdentityServiceProvider#preAuthenticate}
 * must be called for a list of DisplayItem.
 */
package com.ufp.identity4j.data;
