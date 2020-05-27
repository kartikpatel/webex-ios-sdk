// Copyright 2016-2020 Cisco Systems Inc
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.


import Foundation
import XCTest
@testable import WebexSDK


fileprivate class MockJWTStorage: JWTAuthStorage {
    var jwt: String?
    var authenticationInfo: JWTAuthenticationInfo?
}

fileprivate class MockJWTClient: JWTAuthClient {
    var fetchTokenFromJWT_callCount = 0
    var fetchTokenFromJWT_completionHandler_response: ServiceResponse<JWTTokenModel>?
    
    override init() {
        
    }
    
    override func fetchTokenFromJWT(_ jwt: String, queue: DispatchQueue? = nil, completionHandler: @escaping (ServiceResponse<JWTTokenModel>) -> Void) {
        fetchTokenFromJWT_callCount += 1
        
        if let response = fetchTokenFromJWT_completionHandler_response {
            completionHandler(response)
        }
    }
}

class JWTAuthenticatorTests: XCTestCase {
    private static let oneDay: TimeInterval = 24*60*60
    private let yesterday = Date(timeIntervalSinceNow: -JWTAuthenticatorTests.oneDay)
    private let tomorrow = Date(timeIntervalSinceNow: JWTAuthenticatorTests.oneDay)
    private let now = Date()
    private var storage: MockJWTStorage!
    private var client: MockJWTClient!
    private static let testJWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJibGFoIiwiaXNzIjoidGhpc0lzQVRlc3QiLCJleHAiOjQxMDI0NDQ4MDB9.p4frHZUGx8Qi60P77fl09lKCRGoJFNZzUqBm2fKOfC4"
    private let expiredTestJWT = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJibGFoIiwiaXNzIjoidGhpc0lzQVRlc3QiLCJleHAiOjE0NTE2MDY0MDB9.qgOgOrakNKAgvBumc5qwbK_ypEAVRpKi7cZWev1unSY"
    private let jwtWithoutExpiration = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaXNzMSJ9.AwLFa7xpba0YoWRYVqXdTUDSa9bvOA7H7tdmqh7zvlA"
    private let jwtWithTooManySegments = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaXNzMSJ9.AwLFa7xpba0YoWRYVqXdTUDSa9bvOA7H7tdmqh7zvlA.AwLFa7xpba0YoWRYVqXdTUDSa9bvOA7H7tdmqh7zvlA"
    private let jwtWithTooFewSegments = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiaXNzIjoiaXNzMSJ9"
    private let jwtWithBadData = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJZdWiIOLIx%jN9NTY3ODkwIiwiaXNzIjoiaXNzMSJ9.AwLFa7xpba0YoWRYVqXdTUDSa9bvOA7H7tdmqh7zvlA"
    
    override func setUp() {
        storage = MockJWTStorage()
        client = MockJWTClient()
    }
    
    func testWhenValidAccessTokenExistsThenTheAccessTokenIsImmediatelyReturned() {
        let testObject = createTestObject()
        
        storage.authenticationInfo = JWTAuthenticationInfo(accessToken: "accessToken1", accessTokenExpirationDate: tomorrow)
        
        let expect = expectation(description: "access token")
        testObject.accessToken() { accessToken in
            XCTAssertEqual(accessToken, "accessToken1")
            expect.fulfill()
        }
        
        waitForExpectations(timeout: 5) { error in
            XCTAssertNil(error, "access token time out")
        }
    }
    
    func testWhenAccessTokenExistsAndJWTIsExpiredThenNilIsImmediatelyReturnedForAccessToken() {
        let testObject = createTestObject(jwt: expiredTestJWT)
        
        storage.authenticationInfo = JWTAuthenticationInfo(accessToken: "accessToken1", accessTokenExpirationDate: yesterday)
        
        let expect = expectation(description: "access token")
        testObject.accessToken() { [unowned self] accessToken in
            XCTAssertNil(accessToken)
            XCTAssertEqual(self.client.fetchTokenFromJWT_callCount, 0)
            expect.fulfill()
        }
        
        waitForExpectations(timeout: 5) { error in
            XCTAssertNil(error, "access token time out")
        }
    }
    
    func testWhenAccessTokenExpiredButJWTIsValidThenAccessTokenIsRefreshed() {
        let testObject = createTestObject()
        
        storage.authenticationInfo = JWTAuthenticationInfo(accessToken: "accessToken1", accessTokenExpirationDate: yesterday)
        let response = accessTokenResponse(accessToken: "accessToken2")
        client.fetchTokenFromJWT_completionHandler_response = response
        
        let expect = expectation(description: "access token")
        testObject.accessToken() { accessToken in
            XCTAssertEqual(accessToken, "accessToken2")
            expect.fulfill()
        }
        
        waitForExpectations(timeout: 5) { error in
            XCTAssertNil(error, "access token time out")
        }
        
        XCTAssertEqual(client.fetchTokenFromJWT_callCount, 1)
        
        let authInfo = storage.authenticationInfo
        XCTAssertEqual(authInfo?.accessToken, "accessToken2")
        XCTAssertEqual(authInfo?.accessTokenExpirationDate.timeIntervalSinceReferenceDate ?? 0, tomorrow.timeIntervalSinceReferenceDate, accuracy: 1.0)
    }
    
    func testWhenAccessTokenHasNoExpirationDateThenItIsAlwaysAuthorized() {
        let testObject = createTestObject(jwt: jwtWithoutExpiration)
        XCTAssertTrue(testObject.authorized)
        
        let response = accessTokenResponse(accessToken: "accessToken1")
        client.fetchTokenFromJWT_completionHandler_response = response
        
        let expect = expectation(description: "access token")
        testObject.accessToken() { accessToken in
            XCTAssertEqual(accessToken, "accessToken1")
            expect.fulfill()
        }
        
        waitForExpectations(timeout: 5) { error in
            XCTAssertNil(error, "access token time out")
        }
        
        XCTAssertEqual(client.fetchTokenFromJWT_callCount, 1)
    }
    
    func testWhenAccessTokenFetchFailsThenDeauthorized() {
        let testObject = createTestObject()
        
        storage.authenticationInfo = JWTAuthenticationInfo(accessToken: "accessToken1", accessTokenExpirationDate: yesterday)
        let response = ServiceResponse<JWTTokenModel>(nil, Result.failure(WebexError.illegalStatus(reason: "Fetch fails test")))
        client.fetchTokenFromJWT_completionHandler_response = response
        
        let expect = expectation(description: "access token")
        testObject.accessToken() { accessToken in
            XCTAssertEqual(accessToken, nil)
            expect.fulfill()
        }
        
        waitForExpectations(timeout: 5) { error in
            XCTAssertNil(error, "access token time out")
        }
        
        XCTAssertNil(storage.authenticationInfo)
    }
    
    func testWhenDeauthorizedThenAuthInfoIsCleared() {
        storage.authenticationInfo = JWTAuthenticationInfo(accessToken: "accessToken1", accessTokenExpirationDate: tomorrow)
        let testObject = createTestObject()
        
        testObject.deauthorize()
        
        XCTAssertFalse(testObject.authorized)
        XCTAssertNil(storage.authenticationInfo)
    }
    
    func testWhenANewJwtIsSetThenANewAccessTokenIsRetrieved() {
        let testObject = createTestObject()
        
        storage.authenticationInfo = JWTAuthenticationInfo(accessToken: "accessToken1", accessTokenExpirationDate: tomorrow)
        let response = accessTokenResponse(accessToken: "accessToken2")
        client.fetchTokenFromJWT_completionHandler_response = response
        
        testObject.authorizedWith(jwt: jwtWithoutExpiration)
        
        XCTAssertEqual(storage.jwt, jwtWithoutExpiration)
        
        let expect = expectation(description: "access token")
        testObject.accessToken() { accessToken in
            XCTAssertEqual(accessToken, "accessToken2")
            expect.fulfill()
        }
        
        waitForExpectations(timeout: 5) { error in
            XCTAssertNil(error, "access token time out")
        }
    }
    
    func testWhenANewJwtIsSetButHasIncorrectSegmentsThenJwtIsNotAuthorized() {
        let testObject = createTestObject()
        testObject.authorizedWith(jwt: jwtWithTooManySegments)
        
        XCTAssertFalse(testObject.authorized)
        
        let testObject2 = createTestObject()
        testObject2.authorizedWith(jwt: jwtWithTooFewSegments)
        
        XCTAssertFalse(testObject2.authorized)
    }
    
    func testWhenANewJwtIsSetButHasUnparseableDataThenJwtIsNotAuthorized() {
        let testObject = createTestObject(jwt: jwtWithBadData)
        
        XCTAssertFalse(testObject.authorized)
    }
    
    func testWhenRequestTokenTwiceThenCallServiceOnceAndCallsBothCompletionHandlersWithTheResult() {
        let testObject = createTestObject()
        
        let response = accessTokenResponse(accessToken: "accessToken1")
        client.fetchTokenFromJWT_completionHandler_response = response
        
        let expect1 = expectation(description: "access token")
        testObject.accessToken() { accessToken in
            XCTAssertEqual(accessToken, "accessToken1")
            expect1.fulfill()
        }
        
        let expect2 = expectation(description: "access token")
        testObject.accessToken() { accessToken in
            XCTAssertEqual(accessToken, "accessToken1")
            expect2.fulfill()
        }
        
        waitForExpectations(timeout: 5) { error in
            XCTAssertNil(error, "access token time out")
        }
        
        XCTAssertEqual(client.fetchTokenFromJWT_callCount, 1)
    }
    
    func testGivenWeHaveAlreadyReceivedAnAccessTokenWhenWeAskForAnotherThenTheFirstHandlerIsNotCalledAgain() {
        let testObject = createTestObject()
        
        let response = accessTokenResponse(accessToken: "accessToken1")
        client.fetchTokenFromJWT_completionHandler_response = response
        
        var tokenOneCount = 0
        var tokenTwoCount = 0
        
        let expect1 = expectation(description: "access token")
        testObject.accessToken() { _ in
            tokenOneCount += 1
            expect1.fulfill()
        }
        
        testObject.authorizedWith(jwt: jwtWithoutExpiration)
        let expect2 = expectation(description: "access token")
        testObject.accessToken() { _ in
            tokenTwoCount += 1
            expect2.fulfill()
        }
        
        waitForExpectations(timeout: 5) { error in
            XCTAssertNil(error, "access token time out")
        }
        
        XCTAssertEqual(tokenOneCount, 1)
        XCTAssertEqual(tokenTwoCount, 1)
    }
    
    private func createTestObject(jwt: String = testJWT) -> JWTAuthenticator {
        let authenticator = JWTAuthenticator(storage: storage, client: client)
        authenticator.authorizedWith(jwt: jwt)
        return authenticator
    }
    
    private func accessTokenResponse(accessToken: String) -> ServiceResponse<JWTTokenModel> {
        var accessTokenObject = JWTTokenModel(token: accessToken)
        accessTokenObject.tokenCreationDate = now
        accessTokenObject.tokenExpiration = JWTAuthenticatorTests.oneDay
        return ServiceResponse<JWTTokenModel>(nil, Result.success(accessTokenObject))
    }
}
