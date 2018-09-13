import {
  getLangAsObject,
  getLangString,
  nullifyTranslations,
  unnullifyTranslations
} from 'utils';

describe('utils', () => {
  describe('getLangAsObject', () => {
    it('should return object for valid langString', () => {
      const langObj = getLangAsObject('English (en)');
      chai.expect(langObj.name).to.equal('English');
      chai.expect(langObj.code).to.equal('en');
    });

    it('should return undefined for invalid langString', () => {
      chai.expect(getLangAsObject('English')).to.equal(undefined);
      chai.expect(getLangAsObject('(en)')).to.equal(undefined);
      chai.expect(getLangAsObject('English [en]')).to.equal(undefined);
      chai.expect(getLangAsObject('English, en')).to.equal(undefined);
      chai.expect(getLangAsObject('English: en')).to.equal(undefined);
      chai.expect(getLangAsObject('(en) English')).to.equal(undefined);
      chai.expect(getLangAsObject('English (en) (fr) (de)')).to.equal(undefined);
      chai.expect(getLangAsObject('Pizza time!')).to.equal(undefined);
    });

    it('should work properly with getLangString', () => {
      const langObj = getLangAsObject(getLangString({
        name: 'English',
        code: 'en'
      }));
      chai.expect(langObj.name).to.equal('English');
      chai.expect(langObj.code).to.equal('en');
    });
  });

  describe('getLangString', () => {
    it('should return valid langString from langObj', () => {
      const langString = getLangString({
        name: 'English',
        code: 'en'
      });
      chai.expect(langString).to.equal('English (en)');
    });

    it('should return nothing for invalid object', () => {
      const langString = getLangString({
        pizzaType: 2,
        delivery: false
      });
      chai.expect(langString).to.equal(undefined);
    });

    it('should work properly with getLangAsObject', () => {
      const langString = getLangString(getLangAsObject('English (en)'));
      chai.expect(langString).to.equal('English (en)');
    });
  });
});

//  TRANSLATIONS HACK test
describe('translations hack', () => {
  describe('nullifyTranslations', () => {
    it('should return array with null for no translations', () => {
      const test = {
        survey: [{'label': 'Hello'}]
      };
      const target = {
        survey: [{'label': 'Hello'}],
        translations: [null]
      }
      expect(
        nullifyTranslations(test.translations, test.translated, test.survey, test.baseSurvey)
      ).to.deep.equal(target);
    });

    it('should throw if there are unnamed translations', () => {
      const test = {
        survey: [{'label': 'Hello'}],
        translations: [
          null,
          'English (en)'
        ]
      };
      expect(() => {
        nullifyTranslations(test.translations, test.translated, test.survey, test.baseSurvey);
      }).to.throw();
    });

    it('should not reorder anything if survey has same default language as base survey', () => {
      const test = {
        baseSurvey: {_initialParams: {translations_0: 'English (en)'}},
        survey: [
          {
            'label::English (en)': 'Hello',
            'label::Polski (pl)': 'Cześć'
          }
        ],
        translations: [
          'English (en)',
          'Polski (pl)',
        ],
        translated: [
          'label',
          'hint'
        ]
      };
      const target = {
        survey: [
          {
            'label::English (en)': 'Hello',
            'label::Polski (pl)': 'Cześć'
          }
        ],
        translations: [
          null,
          'Polski (pl)',
        ],
        translations_0: 'English (en)'
      }
      expect(
        nullifyTranslations(test.translations, test.translated, test.survey, test.baseSurvey)
      ).to.deep.equal(target);
    });
  });
});
